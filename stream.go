package gosec

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/go/packages"

	"github.com/securego/gosec/v2/issue"
)

// IssueSink receives issues while a scan is running. Issues are delivered as
// soon as the package that produced them finishes, so their order follows
// package completion and is not deterministic. A sink that needs a stable
// order must establish it itself; the review report does so by spilling and
// externally sorting.
//
// WriteIssue is only called from the aggregation goroutine, so a sink does not
// need to be safe for concurrent use.
type IssueSink interface {
	WriteIssue(*issue.Issue) error
}

// SkippedFile records a source file whose content could not be fully parsed.
// The scan continues with the remaining files; these entries are reported so a
// clean result is not mistaken for "this file was scanned and has no
// findings".
type SkippedFile struct {
	File   string
	Errors []Error
}

// SetIssueSink enables streaming mode. When a sink is installed the analyzer
// no longer retains the issues it finds, which keeps memory bounded on large
// repositories. Report still returns the metrics and the loader/parser errors,
// but its issue slice stays empty.
func (gosec *Analyzer) SetIssueSink(sink IssueSink) {
	gosec.issueSink = sink
}

// SkippedFiles returns the files that failed to parse during the scan, sorted
// by file path. It is populated in streaming mode only, because the regular
// report surfaces the same information through its Golang errors section.
func (gosec *Analyzer) SkippedFiles() []SkippedFile {
	return gosec.skipped
}

// ProcessContext is Process with a caller supplied context. Cancelling the
// context stops the workers. Packages that already finished are still
// delivered to the sink, so an interrupted scan keeps everything it produced.
func (gosec *Analyzer) ProcessContext(ctx context.Context, buildTags []string, packagePaths ...string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		pkgPath string
		pkgs    []*packages.Package
		issues  []*issue.Issue
		stats   *Metrics
		errors  map[string][]Error
		skipped []SkippedFile
		err     error
	}

	results := make(chan result, len(packagePaths)) // Buffer for all potential results
	jobs := make(chan string, len(packagePaths))

	// Fill jobs channel and close it to signal no more work
	for _, pkgPath := range packagePaths {
		jobs <- pkgPath
	}
	close(jobs)

	g := errgroup.Group{}
	g.SetLimit(gosec.concurrency)

	worker := func() error {
		for {
			select {
			case pkgPath, ok := <-jobs:
				if !ok {
					return nil // Jobs drained, worker done
				}

				pkgs, err := gosec.load(pkgPath, buildTags)
				if err != nil {
					results <- result{pkgPath: pkgPath, err: err}
					continue
				}

				var funcIssues []*issue.Issue
				funcStats := &Metrics{}
				funcErrors := make(map[string][]Error)
				var funcSkipped []SkippedFile

				for _, pkg := range pkgs {
					if pkg.Name == "" {
						continue
					}

					// In streaming mode, keep a record of unparseable files so
					// the review report can name them. This does not change the
					// scanning behaviour: the same package errors continue to be
					// reported through the regular Golang errors section.
					if gosec.issueSink != nil {
						funcSkipped = append(funcSkipped, collectParseFailures(pkg)...)
					}

					errs, err := ParseErrors(pkg)
					if err != nil {
						results <- result{
							pkgPath: pkgPath,
							err:     fmt.Errorf("parsing errors in pkg %q: %w", pkg.Name, err),
						}
						return nil // Parsing error in worker stops this package
					}
					// Collect parsing errors if any
					if len(errs) > 0 {
						for k, v := range errs {
							funcErrors[k] = append(funcErrors[k], v...)
						}
					}

					// Run AST-based rules (stateless)
					issues, stats, allIgnores := gosec.checkRules(pkg)
					funcIssues = append(funcIssues, issues...)
					funcStats.Merge(stats)

					// Run SSA-based analyzers (stateless)
					ssaIssues, ssaStats := gosec.checkAnalyzers(pkg, allIgnores)
					funcIssues = append(funcIssues, ssaIssues...)
					funcStats.Merge(ssaStats)
				}

				results <- result{
					pkgPath: pkgPath,
					pkgs:    pkgs,
					issues:  funcIssues,
					stats:   funcStats,
					errors:  funcErrors,
					skipped: funcSkipped,
				}
			case <-ctx.Done():
				return ctx.Err() // Early shutdown
			}
		}
	}

	// Start workers
	for i := 0; i < gosec.concurrency; i++ {
		g.Go(worker)
	}

	// Wait for workers; first error cancels context via errgroup
	go func() {
		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			cancel()
		}
		close(results)
	}()

	// Aggregate results
	var sinkErr error
	for r := range results {
		if r.err != nil {
			gosec.AppendError(r.pkgPath, r.err)
		}
		if gosec.issueSink != nil {
			if sinkErr == nil {
				for _, iss := range r.issues {
					if err := gosec.issueSink.WriteIssue(iss); err != nil {
						sinkErr = err
						cancel()
						break
					}
				}
			}
		} else {
			gosec.issues = append(gosec.issues, r.issues...)
		}
		gosec.stats.Merge(r.stats)
		for file, matches := range r.errors {
			gosec.errors[file] = append(gosec.errors[file], matches...)
		}
		if len(r.skipped) > 0 {
			gosec.skipped = append(gosec.skipped, r.skipped...)
		}
	}
	sortErrors(gosec.errors)
	gosec.skipped = dedupeSkipped(gosec.skipped)

	if sinkErr != nil {
		return sinkErr
	}
	return g.Wait() // Return any aggregated error from workers
}

var parsePosRegexp = regexp.MustCompile(`^(.*?)(?::(\w+))?(?::(\w+))?$`)

// collectParseFailures returns the parse errors attached to a package,
// deduplicated by location and message.
func collectParseFailures(pkg *packages.Package) []SkippedFile {
	byFile := make(map[string][]Error)
	for _, pkgErr := range pkg.Errors {
		if pkgErr.Kind != packages.ParseError {
			continue
		}
		file, line, col := parseErrorPosition(pkgErr.Pos, pkg.PkgPath)
		byFile[file] = append(byFile[file], Error{Line: line, Column: col, Err: strings.TrimSpace(pkgErr.Msg)})
	}

	out := make([]SkippedFile, 0, len(byFile))
	for file, errs := range byFile {
		out = append(out, SkippedFile{File: file, Errors: dedupeErrors(errs)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

func parseErrorPosition(pos, fallback string) (string, int, int) {
	file := strings.TrimSpace(pos)
	if file == "" || file == "-" {
		return fallback, 0, 0
	}
	matches := parsePosRegexp.FindStringSubmatch(file)
	if len(matches) == 0 {
		return file, 0, 0
	}
	file = strings.TrimSuffix(matches[1], ":")
	if file == "" || file == "-" {
		file = fallback
	}
	line, col := 0, 0
	if len(matches) > 2 && matches[2] != "" {
		line, _ = strconv.Atoi(matches[2])
	}
	if len(matches) > 3 && matches[3] != "" {
		col, _ = strconv.Atoi(matches[3])
	}
	return file, line, col
}

func dedupeErrors(errs []Error) []Error {
	seen := make(map[Error]struct{}, len(errs))
	out := make([]Error, 0, len(errs))
	for _, err := range errs {
		if _, ok := seen[err]; ok {
			continue
		}
		seen[err] = struct{}{}
		out = append(out, err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		if out[i].Column != out[j].Column {
			return out[i].Column < out[j].Column
		}
		return out[i].Err < out[j].Err
	})
	return out
}

func dedupeSkipped(files []SkippedFile) []SkippedFile {
	if len(files) == 0 {
		return nil
	}
	byFile := make(map[string][]Error)
	for _, f := range files {
		byFile[f.File] = append(byFile[f.File], f.Errors...)
	}
	out := make([]SkippedFile, 0, len(byFile))
	for file, errs := range byFile {
		out = append(out, SkippedFile{File: file, Errors: dedupeErrors(errs)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}
