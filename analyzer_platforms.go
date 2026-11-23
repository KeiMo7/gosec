package gosec

import (
	"fmt"
	"sort"
	"strings"

	"github.com/securego/gosec/v2/issue"
)

// processMultiPlatform scans each platform in turn and merges the findings.
// A platform that fails to load is recorded as uncovered instead of aborting
// the whole run, so the remaining platforms still produce results.
func (gosec *Analyzer) processMultiPlatform(buildTags []string, selection PlatformSelection, platforms []Platform, packagePaths []string) error {
	ordered := SortPlatforms(platforms)
	perPlatform := make(map[Platform][]*issue.Issue, len(ordered))
	statsByPlatform := make(map[Platform]*Metrics, len(ordered))
	report := &PlatformReport{
		Platforms: orderedStrings(ordered),
		Requested: selection.Requested.Strings(),
		Excluded:  selection.Excluded.Strings(),
		Source:    selection.Source,
		Message:   selection.Message,
	}
	if len(report.Requested) == 0 {
		report.Requested = report.Platforms
	}
	if report.Source == "" {
		report.Source = PlatformSourceExplicit
	}

	// The platform dimension must not amplify concurrency: platforms are
	// scanned sequentially and each one uses the same bounded worker pool.
	for _, platform := range ordered {
		results, err := gosec.scanPlatform(buildTags, platform, packagePaths)
		if err != nil {
			report.Failed = append(report.Failed, PlatformFailure{
				Platform: platform.String(),
				Error:    err.Error(),
			})
			continue
		}

		metrics := &Metrics{}
		var platformIssues []*issue.Issue
		var failureReasons []string

		for _, r := range results {
			if r.err != nil {
				failureReasons = append(failureReasons, r.err.Error())
				continue
			}
			platformIssues = append(platformIssues, r.issues...)
			metrics.Merge(r.stats)
			if len(r.errors) > 0 {
				// A package that does not compile on this platform yields an
				// incomplete answer for it. The errors are attributed to the
				// platform (report.Failed) rather than the global error map,
				// so one platform's build failure does not mark the whole
				// project as broken or force a plain failure exit code.
				failureReasons = append(failureReasons, summarizeGoErrors(r.errors)...)
			}
		}

		if len(failureReasons) > 0 {
			report.Failed = append(report.Failed, PlatformFailure{
				Platform: platform.String(),
				Error:    summarizeReasons(failureReasons),
			})
		}
		perPlatform[platform] = platformIssues
		statsByPlatform[platform] = metrics
	}

	merged, platformStats := mergePlatformResults(perPlatform, PlatformSet(ordered))
	for i := range platformStats {
		platform := ordered[i]
		if metrics := statsByPlatform[platform]; metrics != nil {
			platformStats[i].Files = metrics.NumFiles
			platformStats[i].Lines = metrics.NumLines
			platformStats[i].Nosec = metrics.NumNosec
		}
	}
	report.Stats = platformStats
	report.Conflicts = detectVerdictConflicts(perPlatform, PlatformSet(ordered))
	if len(report.Conflicts) > 0 {
		gosec.logger.Printf("Warning: %d location(s) were judged differently across platforms", len(report.Conflicts))
	}
	report.reconcile()

	covered := make(map[string]bool, len(report.Stats))
	for _, s := range report.Stats {
		covered[s.Platform] = true
	}
	for _, f := range report.Failed {
		covered[f.Platform] = false
	}
	missing := make([]string, 0)
	for _, requested := range report.Requested {
		if !covered[requested] {
			missing = append(missing, requested)
		}
	}
	report.Coverage = CoverageInfo{
		Complete: len(missing) == 0,
		Missing:  dedupeStrings(missing),
	}

	gosec.issues = merged
	gosec.stats = &Metrics{}
	for _, metrics := range statsByPlatform {
		// A plain sum would count the same file once per platform, which
		// overstates the scanned input on multi-platform runs. Files and lines
		// describe the largest single platform instead; nosec and findings
		// count the merged result below.
		gosec.stats.NumFiles = max(gosec.stats.NumFiles, metrics.NumFiles)
		gosec.stats.NumLines = max(gosec.stats.NumLines, metrics.NumLines)
		gosec.stats.NumNosec = max(gosec.stats.NumNosec, metrics.NumNosec)
	}
	unsuppressed := 0
	for _, current := range merged {
		if len(current.Suppressions) == 0 {
			unsuppressed++
		}
	}
	gosec.stats.NumFound = unsuppressed
	sortErrors(gosec.errors)
	gosec.platformReport = report
	return nil
}

// summarizeGoErrors renders the first few build errors for a platform so
// failures stay readable in reports.
func summarizeGoErrors(errorsByFile map[string][]Error) []string {
	files := make([]string, 0, len(errorsByFile))
	for file := range errorsByFile {
		files = append(files, file)
	}
	sort.Strings(files)
	var reasons []string
	for _, file := range files {
		for _, e := range errorsByFile[file] {
			reasons = append(reasons, fmt.Sprintf("%s:%d:%d: %s", file, e.Line, e.Column, e.Err))
		}
	}
	return reasons
}

// summarizeReasons joins reasons and caps the number shown.
func summarizeReasons(reasons []string) string {
	reasons = dedupeStrings(reasons)
	const limit = 3
	if len(reasons) <= limit {
		return strings.Join(reasons, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(reasons[:limit], "; "), len(reasons)-limit)
}

// Complete reports whether every requested platform was analyzed.
func (r *PlatformReport) Complete() bool {
	return r != nil && r.Coverage.Complete
}

// FailureSummary renders the uncovered platforms for log output.
func (r *PlatformReport) FailureSummary() string {
	if r == nil || len(r.Failed) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.Failed))
	for _, failure := range r.Failed {
		parts = append(parts, fmt.Sprintf("%s (%s)", failure.Platform, failure.Error))
	}
	return "platforms not covered: " + strings.Join(parts, ", ")
}

func orderedStrings(platforms []Platform) []string {
	out := make([]string, len(platforms))
	for i, p := range platforms {
		out[i] = p.String()
	}
	return out
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
