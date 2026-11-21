package review

import (
	"bufio"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/securego/gosec/v2"
)

// reportHeader is the shared metadata block of both encodings.
type reportHeader struct {
	SchemaVersion string        `json:"schemaVersion"`
	ScanRoot      string        `json:"scanRoot"`
	Excluded      []Exclusion   `json:"excluded,omitempty"`
	Stats         reportStats   `json:"stats"`
	Interrupted   bool          `json:"interrupted,omitempty"`
	Skipped       []SkippedFile `json:"skipped,omitempty"`
	Errors        []errorGroup  `json:"errors,omitempty"`
}

type reportStats struct {
	Files        int            `json:"files"`
	Lines        int            `json:"lines"`
	Findings     int            `json:"findings"`
	Suppressed   int            `json:"suppressed"`
	PathExcluded int            `json:"pathExcluded"`
	Filtered     int            `json:"filteredByThreshold"`
	BySeverity   map[string]int `json:"bySeverity"`
	ByRule       map[string]int `json:"byRule"`
}

type errorGroup struct {
	File   string       `json:"file"`
	Errors []gosecError `json:"errors"`
}

type gosecError struct {
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Error  string `json:"error"`
}

func (b *Builder) header(summary Summary) reportHeader {
	roots := make([]string, 0, len(b.opts.Roots))
	for _, r := range b.opts.Roots {
		roots = append(roots, b.relative(r))
	}
	scanRoot := ""
	if len(roots) > 0 {
		scanRoot = roots[0]
		if scanRoot == "." {
			scanRoot = ""
		}
	}

	h := reportHeader{
		SchemaVersion: SchemaVersion,
		ScanRoot:      scanRoot,
		Excluded:      b.opts.Excluded,
		Interrupted:   summary.Interrupted,
		Stats: reportStats{
			Files:        summary.NumFiles,
			Lines:        summary.NumLines,
			Findings:     b.numFindings,
			Suppressed:   b.numSuppressed,
			PathExcluded: b.numPathExcluded,
			Filtered:     b.numFiltered,
			BySeverity:   copyCounts(b.severityCounts),
			ByRule:       copyCounts(b.ruleCounts),
		},
	}
	for _, skipped := range summary.Skipped {
		h.Skipped = append(h.Skipped, SkippedFile{
			File:   b.relative(skipped.File),
			Errors: toGosecErrors(skipped.Errors),
		})
	}
	sort.Slice(h.Skipped, func(i, j int) bool { return h.Skipped[i].File < h.Skipped[j].File })

	if len(summary.Errors) > 0 {
		files := make([]string, 0, len(summary.Errors))
		for file := range summary.Errors {
			files = append(files, file)
		}
		sort.Strings(files)
		for _, file := range files {
			h.Errors = append(h.Errors, errorGroup{
				File:   b.relative(file),
				Errors: toGosecErrors(summary.Errors[file]),
			})
		}
	}
	return h
}

func toGosecErrors(errs []gosec.Error) []gosecError {
	out := make([]gosecError, 0, len(errs))
	for _, e := range errs {
		out = append(out, gosecError{Line: e.Line, Column: e.Column, Error: e.Err})
	}
	return out
}

func copyCounts(counts map[string]int) map[string]int {
	out := make(map[string]int, len(counts))
	for k, v := range counts {
		out[k] = v
	}
	return out
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func indentJSON(v any, prefix, indent string) (string, error) {
	raw, err := json.MarshalIndent(v, prefix, indent)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ---------------------------------------------------------------------------
// JSON
//
// The encoders stream findings directly from the sorted spills. A view is only
// buffered at the granularity of its innermost element (a file, a severity
// layer or a rule group), never as a whole, so memory stays bounded.

type jsonLocation struct {
	Line     int       `json:"line"`
	EndLine  int       `json:"endLine,omitempty"`
	Column   int       `json:"column"`
	RuleIDs  []string  `json:"ruleIds"`
	Findings []Finding `json:"findings"`
}

type jsonFunction struct {
	Name      string         `json:"name"`
	Locations []jsonLocation `json:"locations"`
}

type jsonFileView struct {
	File      string         `json:"file"`
	Functions []jsonFunction `json:"functions"`
}

type jsonSeverityLayer struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type jsonRuleGroup struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

func (b *Builder) renderJSON(w *bufio.Writer, summary Summary) error {
	header := b.header(summary)
	if _, err := fmt.Fprint(w, "{\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\t\"schemaVersion\": %s,\n", jsonString(header.SchemaVersion)); err != nil {
		return err
	}
	if err := writeHeaderFields(w, header); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, "\t\"views\": {\n"); err != nil {
		return err
	}
	if err := b.renderJSONByFile(w); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, ",\n"); err != nil {
		return err
	}
	if err := b.renderJSONBySeverity(w); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, ",\n"); err != nil {
		return err
	}
	if err := b.renderJSONByRule(w); err != nil {
		return err
	}
	_, err := fmt.Fprint(w, "\n\t}\n}\n")
	return err
}

func writeHeaderFields(w *bufio.Writer, h reportHeader) error {
	fields := []struct {
		name  string
		value any
		omit  bool
	}{
		{"scanRoot", h.ScanRoot, h.ScanRoot == ""},
		{"excluded", h.Excluded, len(h.Excluded) == 0},
		{"stats", h.Stats, false},
		{"interrupted", h.Interrupted, !h.Interrupted},
		{"skipped", h.Skipped, len(h.Skipped) == 0},
		{"errors", h.Errors, len(h.Errors) == 0},
	}
	for _, field := range fields {
		if field.omit {
			continue
		}
		raw, err := indentJSON(field.value, "\t", "\t")
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "\t%s: %s,\n", jsonString(field.name), raw); err != nil {
			return err
		}
	}
	return nil
}

func (b *Builder) renderJSONByFile(w *bufio.Writer) error {
	if _, err := fmt.Fprint(w, "\t\t\"byFile\": ["); err != nil {
		return err
	}
	first := true
	var currentFile string
	var pending []Finding
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		raw, err := indentJSON(buildFileView(currentFile, pending), "\t\t\t", "\t")
		if err != nil {
			return err
		}
		if !first {
			if _, err := fmt.Fprint(w, ","); err != nil {
				return err
			}
		}
		first = false
		if _, err := fmt.Fprint(w, "\n\t\t\t"+raw); err != nil {
			return err
		}
		pending = nil
		return nil
	}
	err := eachFinding(b.orderedPath, func(f Finding) error {
		if currentFile != f.File {
			if err := flush(); err != nil {
				return err
			}
			currentFile = f.File
		}
		pending = append(pending, f)
		return nil
	})
	if err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}
	if !first {
		if _, err := fmt.Fprint(w, "\n\t\t"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprint(w, "]\n")
	return err
}

// buildFileView groups one file's findings by enclosing function and then by
// statement. It holds a single file at a time.
func buildFileView(file string, findings []Finding) jsonFileView {
	view := jsonFileView{File: file}
	var fn *jsonFunction
	var loc *jsonLocation
	for _, f := range findings {
		if fn == nil || fn.Name != f.Function {
			view.Functions = append(view.Functions, jsonFunction{Name: f.Function})
			fn = &view.Functions[len(view.Functions)-1]
			loc = nil
		}
		if loc == nil || loc.Line != f.Line || loc.EndLine != f.EndLine || loc.Column != f.Column {
			fn.Locations = append(fn.Locations, jsonLocation{Line: f.Line, EndLine: f.EndLine, Column: f.Column})
			loc = &fn.Locations[len(fn.Locations)-1]
		}
		loc.Findings = append(loc.Findings, f)
		loc.RuleIDs = appendUnique(loc.RuleIDs, f.RuleID)
	}
	return view
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

func (b *Builder) renderJSONBySeverity(w *bufio.Writer) error {
	if _, err := fmt.Fprint(w, "\t\t\"bySeverity\": ["); err != nil {
		return err
	}
	firstLayer := true
	openLayer := func(severity string, count int) error {
		if !firstLayer {
			if _, err := fmt.Fprint(w, ","); err != nil {
				return err
			}
		}
		firstLayer = false
		raw, err := indentJSON(jsonSeverityLayer{Severity: severity, Count: count}, "\t\t\t", "\t")
		if err != nil {
			return err
		}
		// Splice the findings array into the encoded layer object.
		trimmed := strings.TrimSuffix(strings.TrimSpace(raw), "}")
		_, err = fmt.Fprintf(w, "\n\t\t\t%s,\n\t\t\t\t\"findings\": [", strings.TrimSpace(trimmed))
		return err
	}
	closeLayer := func() error {
		_, err := fmt.Fprint(w, "\n\t\t\t\t]\n\t\t\t}")
		return err
	}

	current := ""
	firstFinding := true
	err := eachFinding(b.severityPath, func(f Finding) error {
		if f.Severity != current {
			if current != "" {
				if err := closeLayer(); err != nil {
					return err
				}
			}
			current = f.Severity
			firstFinding = true
			if err := openLayer(current, b.severityCounts[current]); err != nil {
				return err
			}
		}
		if !firstFinding {
			if _, err := fmt.Fprint(w, ","); err != nil {
				return err
			}
		}
		firstFinding = false
		raw, err := indentJSON(f, "\t\t\t\t\t", "\t")
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(w, "\n\t\t\t\t\t"+raw)
		return err
	})
	if err != nil {
		return err
	}
	if current != "" {
		if err := closeLayer(); err != nil {
			return err
		}
	}
	if !firstLayer {
		if _, err := fmt.Fprint(w, "\n\t\t"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprint(w, "]\n")
	return err
}

func (b *Builder) renderJSONByRule(w *bufio.Writer) error {
	if _, err := fmt.Fprint(w, "\t\t\"byRule\": ["); err != nil {
		return err
	}
	firstGroup := true
	openGroup := func(ruleID, severity string, count int) error {
		if !firstGroup {
			if _, err := fmt.Fprint(w, ","); err != nil {
				return err
			}
		}
		firstGroup = false
		raw, err := indentJSON(jsonRuleGroup{RuleID: ruleID, Severity: severity, Count: count}, "\t\t\t", "\t")
		if err != nil {
			return err
		}
		trimmed := strings.TrimSuffix(strings.TrimSpace(raw), "}")
		_, err = fmt.Fprintf(w, "\n\t\t\t%s,\n\t\t\t\t\"findings\": [", strings.TrimSpace(trimmed))
		return err
	}
	closeGroup := func() error {
		_, err := fmt.Fprint(w, "\n\t\t\t\t]\n\t\t\t}")
		return err
	}

	current := ""
	firstFinding := true
	err := eachFinding(b.rulePath, func(f Finding) error {
		if f.RuleID != current {
			if current != "" {
				if err := closeGroup(); err != nil {
					return err
				}
			}
			current = f.RuleID
			firstFinding = true
			if err := openGroup(current, f.Severity, b.ruleCounts[current]); err != nil {
				return err
			}
		}
		if !firstFinding {
			if _, err := fmt.Fprint(w, ","); err != nil {
				return err
			}
		}
		firstFinding = false
		raw, err := indentJSON(f, "\t\t\t\t\t", "\t")
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(w, "\n\t\t\t\t\t"+raw)
		return err
	})
	if err != nil {
		return err
	}
	if current != "" {
		if err := closeGroup(); err != nil {
			return err
		}
	}
	if !firstGroup {
		if _, err := fmt.Fprint(w, "\n\t\t"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprint(w, "]\n")
	return err
}

// ---------------------------------------------------------------------------
// Text

func (b *Builder) renderText(w *bufio.Writer, summary Summary) error {
	header := b.header(summary)

	if _, err := fmt.Fprintln(w, "gosec review report"); err != nil {
		return err
	}
	if header.ScanRoot != "" {
		if _, err := fmt.Fprintf(w, "Scan root: %s\n", header.ScanRoot); err != nil {
			return err
		}
	}
	if len(header.Excluded) > 0 {
		if _, err := fmt.Fprintln(w, "Excluded from the scan:"); err != nil {
			return err
		}
		for _, ex := range header.Excluded {
			noun := "directories"
			if ex.Total == 1 {
				noun = "directory"
			}
			line := fmt.Sprintf("  %s (%d %s)", ex.Pattern, ex.Total, noun)
			if ex.Truncated {
				line += fmt.Sprintf(", listing %d", len(ex.Dirs))
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
			for _, dir := range ex.Dirs {
				if _, err := fmt.Fprintf(w, "    - %s\n", dir); err != nil {
					return err
				}
			}
		}
	}

	if len(header.Skipped) > 0 {
		if _, err := fmt.Fprintln(w, "\nSkipped files (could not be parsed, not scanned):"); err != nil {
			return err
		}
		for _, skipped := range header.Skipped {
			if _, err := fmt.Fprintf(w, "  %s\n", skipped.File); err != nil {
				return err
			}
			for _, e := range skipped.Errors {
				if _, err := fmt.Fprintf(w, "    %d:%d %s\n", e.Line, e.Column, e.Error); err != nil {
					return err
				}
			}
		}
	}

	if len(header.Errors) > 0 {
		if _, err := fmt.Fprintln(w, "\nLoader errors:"); err != nil {
			return err
		}
		for _, group := range header.Errors {
			if _, err := fmt.Fprintf(w, "  %s\n", group.File); err != nil {
				return err
			}
			for _, e := range group.Errors {
				if _, err := fmt.Fprintf(w, "    %d:%d %s\n", e.Line, e.Column, e.Error); err != nil {
					return err
				}
			}
		}
	}

	if _, err := fmt.Fprintf(w, "\nSummary: %d findings in %d files (%d lines), %d suppressed, %d excluded by path rules, %d below the severity/confidence threshold\n",
		header.Stats.Findings, header.Stats.Files, header.Stats.Lines, header.Stats.Suppressed, header.Stats.PathExcluded, header.Stats.Filtered); err != nil {
		return err
	}
	if header.Interrupted {
		if _, err := fmt.Fprintln(w, "WARNING: the scan was interrupted; this report contains only the findings produced before the interruption."); err != nil {
			return err
		}
	}

	if err := b.renderTextBySeverity(w); err != nil {
		return err
	}
	if err := b.renderTextByFile(w); err != nil {
		return err
	}
	return b.renderTextByRule(w)
}

func (b *Builder) renderTextBySeverity(w *bufio.Writer) error {
	if _, err := fmt.Fprintln(w, "\n== By severity =="); err != nil {
		return err
	}
	current := ""
	err := eachFinding(b.severityPath, func(f Finding) error {
		if f.Severity != current {
			if current != "" {
				if _, err := fmt.Fprintln(w); err != nil {
					return err
				}
			}
			current = f.Severity
			if _, err := fmt.Fprintf(w, "-- %s (%d) --\n", current, b.severityCounts[current]); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(w, "  %s:%d:%d  %s  %s\n", f.File, f.Line, f.Column, f.RuleID, f.What)
		return err
	})
	return err
}

func (b *Builder) renderTextByFile(w *bufio.Writer) error {
	if _, err := fmt.Fprintln(w, "\n== By file =="); err != nil {
		return err
	}
	var currentFile string
	var currentFn string
	var currentLoc string
	err := eachFinding(b.orderedPath, func(f Finding) error {
		if f.File != currentFile {
			currentFile = f.File
			currentFn = "\x00"
			if _, err := fmt.Fprintf(w, "\n%s\n", f.File); err != nil {
				return err
			}
		}
		if f.Function != currentFn {
			currentFn = f.Function
			label := currentFn
			if label == "" {
				label = "(top level)"
			}
			if _, err := fmt.Fprintf(w, "  %s\n", label); err != nil {
				return err
			}
		}
		locKey := fmt.Sprintf("%d:%d-%d", f.Line, f.EndLine, f.Column)
		if locKey != currentLoc {
			currentLoc = locKey
			if _, err := fmt.Fprintf(w, "    line %d, column %d\n", f.Line, f.Column); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(w, "      %-6s %-12s %s\n", f.RuleID, f.Severity, f.What)
		return err
	})
	return err
}

func (b *Builder) renderTextByRule(w *bufio.Writer) error {
	if _, err := fmt.Fprintln(w, "\n== By rule =="); err != nil {
		return err
	}
	current := ""
	err := eachFinding(b.rulePath, func(f Finding) error {
		if f.RuleID != current {
			if current != "" {
				if _, err := fmt.Fprintln(w); err != nil {
					return err
				}
			}
			current = f.RuleID
			if _, err := fmt.Fprintf(w, "-- %s (%d findings, %s) --\n", current, b.ruleCounts[current], f.Severity); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(w, "  %s:%d:%d  %s\n", f.File, f.Line, f.Column, f.What)
		return err
	})
	return err
}
