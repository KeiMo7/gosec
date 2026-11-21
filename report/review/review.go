// Package review organizes gosec findings for code review instead of for
// machine consumption. Ordinary gosec reports emit one record per finding, so
// the same rule firing three times inside one function shows up as three
// unrelated lines, and findings from different rules on the same statement
// never meet.
//
// The review report keeps the same findings but offers three cross-referenced
// views over them:
//
//   - byFile: findings grouped by file and statement, so every rule that hits
//     a given location is visible together;
//   - bySeverity: findings layered HIGH → MEDIUM → LOW, each layer in a stable
//     order;
//   - byRule: all findings of a rule aggregated across files.
//
// Every finding carries a key that is a pure function of the rule, the
// location relative to the scan root, the finding text and its scores. The key
// does not depend on scan time, concurrency, or which other findings were
// present, so the same problem can be recognized across views and across scan
// subsets.
//
// The builder consumes findings as they are produced and spills them to a
// temporary directory. The three views are produced by a bounded-memory
// external merge sort, so results for repositories with tens of thousands of
// files are never held in memory as a whole. The final report is assembled in
// a temporary file and renamed into place: an interrupted scan leaves either
// the previous report untouched or a complete, well-formed report containing
// everything produced so far.
package review

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/cwe"
	"github.com/securego/gosec/v2/issue"
)

// SchemaVersion identifies the review report layout. It changes only when an
// existing field changes meaning or disappears.
const SchemaVersion = "1"

// Format selects the review report encoding.
type Format string

const (
	// FormatText is a human readable report meant for review comments.
	FormatText Format = "text"
	// FormatJSON is the structured report with all three views.
	FormatJSON Format = "json"
)

// Exclusion documents a directory range that was removed from the scan. Dirs
// are relative to the scan roots, so the report never leaks absolute paths.
type Exclusion struct {
	Pattern   string   `json:"pattern"`
	Total     int      `json:"total"`
	Dirs      []string `json:"dirs"`
	Truncated bool     `json:"truncated,omitempty"`
}

// SkippedFile is a source file the loader could not parse, relative to the
// scan root. The scan continues without it; it is listed so a clean result is
// not mistaken for "this file was scanned and has no findings".
type SkippedFile struct {
	File   string       `json:"file"`
	Errors []gosecError `json:"errors"`
}

// Options configures a Builder.
type Options struct {
	// OutputPath is the report destination. It is validated before the scan
	// starts, so an unwritable target fails fast.
	OutputPath string
	// Format is FormatText (default) or FormatJSON.
	Format Format
	// Roots are the absolute scan roots used to relativize file paths.
	Roots []string
	// Excluded documents directories removed from the scan.
	Excluded []Exclusion
	// ShouldExclude applies the same path-based rule exclusions the ordinary
	// report uses. It may be nil.
	ShouldExclude func(file, ruleID string) bool
	// MinSeverity and MinConfidence mirror the -severity/-confidence flags so
	// the review report contains the same findings the regular report would.
	// Zero values (issue.Low) keep everything.
	MinSeverity   issue.Score
	MinConfidence issue.Score
	// CaptureLegacy keeps a full copy of every issue as it was produced, so
	// the regular report can still be written when the review report is
	// enabled. It costs disk, not memory, and Issues reads it back only if the
	// caller asks for the regular output.
	CaptureLegacy bool
}

// Summary is filled in by the caller once scanning has finished (or was
// interrupted).
type Summary struct {
	Skipped     []gosec.SkippedFile
	Errors      map[string][]gosec.Error
	NumFiles    int
	NumLines    int
	Interrupted bool
}

// Finding is one issue, relative to the scan root.
type Finding struct {
	Key        string `json:"key"`
	RuleID     string `json:"ruleId"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	EndLine    int    `json:"endLine,omitempty"`
	Column     int    `json:"column"`
	Function   string `json:"function,omitempty"`
	What       string `json:"what"`
	NoSec      bool   `json:"nosec,omitempty"`
}

type recordFile struct {
	file   *os.File
	writer *bufio.Writer
	enc    *json.Encoder
}

// Builder accumulates findings and writes the review report.
type Builder struct {
	opts     Options
	outDir   string
	spillDir string

	raw    *recordFile
	legacy *recordFile

	// moduleRoots caches, per directory, the nearest ancestor holding a go.mod.
	// The finding key is relative to that root so the same problem has the same
	// identity whether the scan covered the whole module or only one package.
	moduleRoots map[string]string

	// Derived at finalize time.
	orderedPath  string
	severityPath string
	rulePath     string

	severityCounts  map[string]int
	ruleCounts      map[string]int
	numFindings     int
	numSuppressed   int
	numPathExcluded int
	numFiltered     int

	finalized bool
}

// New prepares the report destination and the spill directory. It returns an
// error before any scanning happens when the target cannot be written.
func New(opts Options) (*Builder, error) {
	if opts.OutputPath == "" {
		return nil, fmt.Errorf("review report output path is empty")
	}
	if opts.Format == "" {
		opts.Format = FormatText
	}
	if opts.Format != FormatText && opts.Format != FormatJSON {
		return nil, fmt.Errorf("invalid review report format %q: valid options are text, json", opts.Format)
	}

	outDir := filepath.Dir(opts.OutputPath)
	info, err := os.Stat(outDir)
	if err != nil {
		return nil, fmt.Errorf("review report directory %q is not usable: %w", outDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("review report directory %q is not a directory", outDir)
	}
	if existing, err := os.Stat(opts.OutputPath); err == nil {
		if existing.IsDir() {
			return nil, fmt.Errorf("review report target %q is a directory", opts.OutputPath)
		}
		// Probe writability without truncating an existing report; the final
		// write is an atomic rename over it.
		probe, err := os.OpenFile(opts.OutputPath, os.O_WRONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("review report target %q is not writable: %w", opts.OutputPath, err)
		}
		_ = probe.Close()
	}

	spillDir, err := os.MkdirTemp(outDir, ".gosec-review-spill-")
	if err != nil {
		return nil, fmt.Errorf("cannot create review report workspace next to %q: %w", opts.OutputPath, err)
	}

	b := &Builder{
		opts:           opts,
		outDir:         outDir,
		spillDir:       spillDir,
		severityCounts: make(map[string]int),
		ruleCounts:     make(map[string]int),
		moduleRoots:    make(map[string]string),
	}
	raw, err := b.newRecordFile("raw")
	if err != nil {
		b.Close()
		return nil, err
	}
	b.raw = raw
	if opts.CaptureLegacy {
		legacy, err := b.newRecordFile("legacy")
		if err != nil {
			b.Close()
			return nil, err
		}
		b.legacy = legacy
	}
	return b, nil
}

// WriteIssue implements gosec.IssueSink. Findings are appended to the raw
// spill; no sorting happens here, so memory use is independent of the result
// size and of the order findings arrive in.
func (b *Builder) WriteIssue(iss *issue.Issue) error {
	if b.finalized {
		return fmt.Errorf("review report already finalized")
	}
	if iss == nil {
		return nil
	}
	if b.legacy != nil {
		if err := b.legacy.enc.Encode(toLegacyIssue(iss)); err != nil {
			return fmt.Errorf("writing legacy issue spill: %w", err)
		}
	}
	if len(iss.Suppressions) > 0 {
		// Match the ordinary text report: suppressed findings are not shown.
		b.numSuppressed++
		return nil
	}
	if b.opts.ShouldExclude != nil && b.opts.ShouldExclude(iss.File, iss.RuleID) {
		b.numPathExcluded++
		return nil
	}
	if iss.Severity < b.opts.MinSeverity || iss.Confidence < b.opts.MinConfidence {
		b.numFiltered++
		return nil
	}

	f := b.newFinding(iss)
	if err := b.raw.enc.Encode(f); err != nil {
		return fmt.Errorf("writing review spill: %w", err)
	}
	return nil
}

func (b *Builder) newFinding(iss *issue.Issue) Finding {
	file := b.relative(iss.File)
	line, endLine := parseLineRange(iss.Line)
	col := atoi(iss.Col)
	severity := iss.Severity.String()
	confidence := iss.Confidence.String()
	what := iss.What

	return Finding{
		Key:        issueKey(iss.RuleID, b.keyPath(iss.File, file), line, endLine, col, severity, confidence, what),
		RuleID:     iss.RuleID,
		Severity:   severity,
		Confidence: confidence,
		File:       file,
		Line:       line,
		EndLine:    endLine,
		Column:     col,
		What:       what,
		NoSec:      iss.NoSec,
	}
}

// keyPath is the path used inside a finding key. It is relative to the nearest
// module root so that scanning a package and scanning the whole module assign
// the same key to the same finding. It falls back to the report path when no
// go.mod can be found.
func (b *Builder) keyPath(absFile, reportPath string) string {
	if !filepath.IsAbs(absFile) {
		return reportPath
	}
	root := b.moduleRoot(filepath.Dir(absFile))
	if root == "" {
		return reportPath
	}
	rel, err := filepath.Rel(root, absFile)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return reportPath
	}
	return filepath.ToSlash(rel)
}

// moduleRoot returns the nearest ancestor directory of dir that contains a
// go.mod, or "" when there is none.
func (b *Builder) moduleRoot(dir string) string {
	if root, ok := b.moduleRoots[dir]; ok {
		return root
	}
	var chain []string
	root := ""
	for current := dir; ; {
		if cached, ok := b.moduleRoots[current]; ok {
			root = cached
			break
		}
		chain = append(chain, current)
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			root = current
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	for _, entry := range chain {
		b.moduleRoots[entry] = root
	}
	return root
}

func (b *Builder) newRecordFile(base string) (*recordFile, error) {
	f, err := os.CreateTemp(b.spillDir, base+"-*")
	if err != nil {
		return nil, fmt.Errorf("creating review spill: %w", err)
	}
	w := bufio.NewWriterSize(f, 64*1024)
	return &recordFile{file: f, writer: w, enc: json.NewEncoder(w)}, nil
}

func (r *recordFile) close() {
	if r == nil {
		return
	}
	_ = r.writer.Flush()
	_ = r.file.Close()
}

// closeErr flushes and closes, surfacing write errors that buffering would
// otherwise hide.
func (r *recordFile) closeErr() error {
	if r == nil {
		return nil
	}
	if err := r.writer.Flush(); err != nil {
		_ = r.file.Close()
		return fmt.Errorf("flushing review spill: %w", err)
	}
	if err := r.file.Close(); err != nil {
		return fmt.Errorf("closing review spill: %w", err)
	}
	return nil
}

// Finalize writes the complete report and atomically replaces the output
// path. Calling Finalize after an interrupted scan still produces a
// well-formed report containing every finding written so far.
func (b *Builder) Finalize(summary Summary) error {
	if b.finalized {
		return fmt.Errorf("review report already finalized")
	}
	b.finalized = true
	// Close is not deferred: callers may also defer it, and the temporary
	// directory must survive until Finalize has installed the report.

	if b.raw == nil {
		return fmt.Errorf("review report has no spill file")
	}
	if err := b.raw.writer.Flush(); err != nil {
		return fmt.Errorf("flushing review spill: %w", err)
	}
	rawPath := b.raw.file.Name()
	b.raw.close()

	// Pass 1: order by file/statement and drop duplicate findings. The same
	// problem reported twice (for example a file included by two package
	// variants) has the same key and collapses to one record.
	ordered, err := b.newSortedFile("ordered", rawPath, compareByLocation, true, b.attachFunction())
	if err != nil {
		return err
	}
	b.orderedPath = ordered

	if err := b.collectCounts(); err != nil {
		return err
	}

	// Pass 2 and 3 produce the other two orders from the deduplicated stream.
	if b.severityPath, err = b.newSortedFile("severity", ordered, compareBySeverity, false, nil); err != nil {
		return err
	}
	if b.rulePath, err = b.newSortedFile("rule", ordered, compareByRule, false, nil); err != nil {
		return err
	}

	assembly, err := os.CreateTemp(b.outDir, ".gosec-review-*")
	if err != nil {
		return fmt.Errorf("creating review report: %w", err)
	}
	assemblyPath := assembly.Name()
	writeErr := func() error {
		w := bufio.NewWriterSize(assembly, 64*1024)
		var err error
		if b.opts.Format == FormatJSON {
			err = b.renderJSON(w, summary)
		} else {
			err = b.renderText(w, summary)
		}
		if err != nil {
			return err
		}
		return w.Flush()
	}()
	if writeErr == nil {
		writeErr = assembly.Sync()
	}
	closeErr := assembly.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(assemblyPath)
		return writeErr
	}
	if err := os.Rename(assemblyPath, b.opts.OutputPath); err != nil {
		_ = os.Remove(assemblyPath)
		return fmt.Errorf("installing review report: %w", err)
	}
	return nil
}

func (b *Builder) collectCounts() error {
	return eachFinding(b.orderedPath, func(f Finding) error {
		b.numFindings++
		b.severityCounts[f.Severity]++
		b.ruleCounts[f.RuleID]++
		return nil
	})
}

// Close releases temporary resources. It is safe to call more than once.
func (b *Builder) Close() {
	if b.spillDir == "" {
		return
	}
	if b.raw != nil {
		b.raw.close()
		b.raw = nil
	}
	if b.legacy != nil {
		b.legacy.close()
		b.legacy = nil
	}
	_ = os.RemoveAll(b.spillDir)
	b.spillDir = ""
}

func (b *Builder) relative(file string) string {
	clean := filepath.Clean(file)
	if !filepath.IsAbs(clean) {
		return filepath.ToSlash(clean)
	}
	best := ""
	bestLen := -1
	for _, root := range b.opts.Roots {
		if root == "" {
			continue
		}
		if rel, err := filepath.Rel(root, clean); err == nil {
			if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
				continue
			}
			if len(root) > bestLen {
				best, bestLen = rel, len(root)
			}
		}
	}
	if best == "" {
		base := ""
		if len(b.opts.Roots) > 0 {
			base = b.opts.Roots[0]
		}
		if base == "" {
			base, _ = os.Getwd()
		}
		if rel, err := filepath.Rel(base, clean); err == nil {
			best = rel
		} else {
			best = filepath.Base(clean)
		}
	}
	return filepath.ToSlash(best)
}

// issueKey builds a stable identity for a finding. It intentionally excludes
// anything that depends on the scan run (timestamps, goroutine order, or the
// presence of other findings).
func issueKey(ruleID, file string, line, endLine, col int, severity, confidence, what string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00%s\x00%s",
		ruleID, file, line, endLine, col, severity, confidence, what)
	return fmt.Sprintf("%s@%s:%d:%d#%s", ruleID, file, line, col, hex.EncodeToString(h.Sum(nil))[:8])
}

func parseLineRange(line string) (int, int) {
	parts := strings.Split(line, "-")
	start := atoi(parts[0])
	end := start
	if len(parts) > 1 {
		end = atoi(parts[1])
	}
	return start, end
}

// Issues returns the issues exactly as they were produced, in scan order. It
// exists for callers that additionally need the regular issue-per-record
// report; the review report itself never calls it.
func (b *Builder) Issues() ([]*issue.Issue, error) {
	if b.legacy == nil {
		return nil, fmt.Errorf("legacy issue capture was not enabled")
	}
	if err := b.legacy.writer.Flush(); err != nil {
		return nil, fmt.Errorf("flushing legacy issue spill: %w", err)
	}
	path := b.legacy.file.Name()

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening legacy issue spill: %w", err)
	}
	defer f.Close() // #nosec G307

	out := make([]*issue.Issue, 0)
	dec := json.NewDecoder(bufio.NewReaderSize(f, 64*1024))
	for {
		var wire legacyIssue
		err := dec.Decode(&wire)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading legacy issue spill: %w", err)
		}
		out = append(out, wire.issue())
	}
	return out, nil
}

// legacyIssue is the on-disk form of a regular issue. issue.Score marshals to
// a string but has no unmarshaller, so the capture stores it explicitly and
// restores the score on read.
type legacyIssue struct {
	Severity     string                  `json:"severity"`
	Confidence   string                  `json:"confidence"`
	Cwe          *cwe.Weakness           `json:"cwe"`
	RuleID       string                  `json:"rule_id"`
	What         string                  `json:"details"`
	File         string                  `json:"file"`
	Code         string                  `json:"code"`
	Line         string                  `json:"line"`
	Col          string                  `json:"column"`
	NoSec        bool                    `json:"nosec"`
	Suppressions []issue.SuppressionInfo `json:"suppressions"`
	Autofix      string                  `json:"autofix,omitempty"`
}

func toLegacyIssue(iss *issue.Issue) legacyIssue {
	return legacyIssue{
		Severity:     iss.Severity.String(),
		Confidence:   iss.Confidence.String(),
		Cwe:          iss.Cwe,
		RuleID:       iss.RuleID,
		What:         iss.What,
		File:         iss.File,
		Code:         iss.Code,
		Line:         iss.Line,
		Col:          iss.Col,
		NoSec:        iss.NoSec,
		Suppressions: iss.Suppressions,
		Autofix:      iss.Autofix,
	}
}

func (w legacyIssue) issue() *issue.Issue {
	return &issue.Issue{
		Severity:     scoreFromString(w.Severity),
		Confidence:   scoreFromString(w.Confidence),
		Cwe:          w.Cwe,
		RuleID:       w.RuleID,
		What:         w.What,
		File:         w.File,
		Code:         w.Code,
		Line:         w.Line,
		Col:          w.Col,
		NoSec:        w.NoSec,
		Suppressions: w.Suppressions,
		Autofix:      w.Autofix,
	}
}

func scoreFromString(s string) issue.Score {
	switch s {
	case "HIGH":
		return issue.High
	case "MEDIUM":
		return issue.Medium
	default:
		return issue.Low
	}
}

// NumFindings returns the number of findings in the report, which is what the
// exit code is derived from.
func (b *Builder) NumFindings() int {
	return b.numFindings
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func severityRank(severity string) int {
	switch severity {
	case "HIGH":
		return 0
	case "MEDIUM":
		return 1
	case "LOW":
		return 2
	default:
		return 3
	}
}

func compareByLocation(a, b Finding) int {
	return compareInts(
		strings.Compare(a.File, b.File),
		compareNums(a.Line, b.Line),
		compareNums(a.EndLine, b.EndLine),
		compareNums(a.Column, b.Column),
		strings.Compare(a.RuleID, b.RuleID),
		strings.Compare(a.What, b.What),
		strings.Compare(a.Severity, b.Severity),
		strings.Compare(a.Confidence, b.Confidence),
		strings.Compare(a.Key, b.Key),
	)
}

func compareBySeverity(a, b Finding) int {
	return compareInts(
		compareNums(severityRank(a.Severity), severityRank(b.Severity)),
		strings.Compare(a.File, b.File),
		compareNums(a.Line, b.Line),
		compareNums(a.EndLine, b.EndLine),
		compareNums(a.Column, b.Column),
		strings.Compare(a.RuleID, b.RuleID),
		strings.Compare(a.What, b.What),
		strings.Compare(a.Key, b.Key),
	)
}

func compareByRule(a, b Finding) int {
	return compareInts(
		strings.Compare(a.RuleID, b.RuleID),
		strings.Compare(a.File, b.File),
		compareNums(a.Line, b.Line),
		compareNums(a.EndLine, b.EndLine),
		compareNums(a.Column, b.Column),
		strings.Compare(a.What, b.What),
		strings.Compare(a.Severity, b.Severity),
		strings.Compare(a.Key, b.Key),
	)
}

func compareNums(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareInts(parts ...int) int {
	for _, p := range parts {
		if p != 0 {
			return p
		}
	}
	return 0
}
