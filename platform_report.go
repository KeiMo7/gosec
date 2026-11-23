package gosec

import (
	"fmt"
	"slices"
	"strings"

	"github.com/securego/gosec/v2/issue"
)

// PlatformFailure records that one target platform could not be analyzed. A
// failed platform is not fatal: the remaining platforms still produce results
// and the failure is surfaced in the report and exit code.
type PlatformFailure struct {
	Platform string `json:"platform"`
	Error    string `json:"error"`
}

// PlatformStats holds the per-platform counters that make a merged,
// multi-platform result reconcilable.
type PlatformStats struct {
	// Platform is the canonical GOOS/GOARCH name.
	Platform string `json:"platform"`
	// Files, Lines and Nosec mirror the regular scan metrics for this target.
	Files int `json:"files"`
	Lines int `json:"lines"`
	Nosec int `json:"nosec"`
	// Issues is the number of findings observed for this platform before any
	// cross-platform merging.
	Issues int `json:"issues"`
	// Unique is the number of findings on this platform that were new with
	// respect to the platforms merged before it.
	Unique int `json:"unique"`
	// Duplicates is Issues - Unique, i.e. how many findings this platform
	// shared with an earlier platform.
	Duplicates int `json:"duplicates"`
}

// Reconciliation makes the accounting of a multi-platform scan auditable:
// the per-platform hit count, the merged issue count and the duplicate count
// must satisfy PerPlatformTotal == Merged + Duplicates.
type Reconciliation struct {
	// PerPlatformTotal is the sum of per-platform issue counts.
	PerPlatformTotal int `json:"per_platform_total"`
	// Merged is the number of issues in the final, de-duplicated result.
	Merged int `json:"merged"`
	// Duplicates is PerPlatformTotal - Merged.
	Duplicates int `json:"duplicates"`
	// Balanced reports whether the identity holds.
	Balanced bool `json:"balanced"`
}

// VerdictConflict records a violation of the platform-independence rule: the
// same rule at the same source location produced a different severity or
// confidence on different platforms. Rules must not let the target platform
// change their judgement, so this is surfaced instead of silently collapsed.
type VerdictConflict struct {
	RuleID    string   `json:"rule_id"`
	File      string   `json:"file"`
	Line      string   `json:"line"`
	Column    string   `json:"column"`
	Platforms []string `json:"platforms"`
	Verdicts  []string `json:"verdicts"`
}

// PlatformReport is the aggregate result of a multi-platform scan.
type PlatformReport struct {
	// Platforms lists the platforms that were actually analyzed, in canonical
	// order.
	Platforms []string `json:"platforms"`
	// Requested lists the platforms asked for before any budget clipping.
	Requested []string `json:"requested"`
	// Excluded lists requested platforms dropped to fit the platform budget.
	Excluded []string `json:"excluded,omitempty"`
	// Source records whether the set was explicit, inferred or the host
	// fallback.
	Source string `json:"source"`
	// Message explains inference, clipping or host fallback. Empty when the
	// selection was explicit and complete.
	Message string `json:"message,omitempty"`
	// Stats carries one entry per analyzed platform.
	Stats []PlatformStats `json:"stats"`
	// Failed lists the platforms that could not be loaded or analyzed.
	Failed []PlatformFailure `json:"failed,omitempty"`
	// Coverage records whether every requested platform was analyzed.
	Coverage CoverageInfo `json:"coverage"`
	// Conflicts lists locations whose verdict differs between platforms. It
	// must stay empty: rules are required to be platform independent.
	Conflicts []VerdictConflict `json:"conflicts,omitempty"`
	// Reconciliation accounts for the merged issues.
	Reconciliation Reconciliation `json:"reconciliation"`
}

// CoverageInfo states whether a scan is complete with respect to the
// requested platform set.
type CoverageInfo struct {
	Complete bool `json:"complete"`
	// Missing lists platforms that were requested but not covered, either
	// because they failed or were clipped by the budget.
	Missing []string `json:"missing,omitempty"`
}

// issueKey identifies an issue independent of the platform it was found on.
// The rule, file, location and message determine identity; severity and
// confidence are part of the key so that two platforms cannot silently
// collapse issues at the same spot that differ in judgement. Rules are
// required to be platform independent, and this key makes a violation of that
// requirement visible instead of hiding it.
type issueKey struct {
	ruleID   string
	file     string
	line     string
	col      string
	what     string
	severity issue.Score
	conf     issue.Score
}

func makeIssueKey(i *issue.Issue) issueKey {
	return issueKey{
		ruleID:   i.RuleID,
		file:     i.File,
		line:     i.Line,
		col:      i.Col,
		what:     i.What,
		severity: i.Severity,
		conf:     i.Confidence,
	}
}

// mergePlatformResults folds per-platform issue lists into one. Ordering is
// preserved: the first platform to report an issue determines its position,
// platforms are merged in canonical order, and the merged issue records every
// platform that hit it. A nil or single-entry input returns the issues
// untouched, which keeps single-platform output byte-for-byte identical.
func mergePlatformResults(perPlatform map[Platform][]*issue.Issue, platforms PlatformSet) ([]*issue.Issue, []PlatformStats) {
	ordered := SortPlatforms(platforms)

	merged := make([]*issue.Issue, 0)
	index := make(map[issueKey]int)
	stats := make([]PlatformStats, 0, len(ordered))

	for _, platform := range ordered {
		issues := perPlatform[platform]
		entry := PlatformStats{Platform: platform.String(), Issues: len(issues)}
		for _, current := range issues {
			key := makeIssueKey(current)
			if pos, found := index[key]; found {
				target := merged[pos]
				if !slices.Contains(target.Platforms, platform.String()) {
					target.Platforms = append(target.Platforms, platform.String())
				}
				entry.Duplicates++
				continue
			}
			clone := *current
			clone.Platforms = []string{platform.String()}
			index[key] = len(merged)
			merged = append(merged, &clone)
			entry.Unique++
		}
		stats = append(stats, entry)
	}
	return merged, stats
}

// verdictKey identifies a source location/rule pair regardless of the verdict.
type verdictKey struct {
	ruleID string
	file   string
	line   string
	col    string
	what   string
}

// detectVerdictConflicts finds locations where the same rule produced
// different severities or confidences on different platforms. Such a conflict
// violates the requirement that the platform dimension never changes a rule's
// judgement.
func detectVerdictConflicts(perPlatform map[Platform][]*issue.Issue, platforms PlatformSet) []VerdictConflict {
	type record struct {
		verdicts map[issueKey][]string
	}
	byLocation := make(map[verdictKey]*record)
	for _, platform := range SortPlatforms(platforms) {
		for _, current := range perPlatform[platform] {
			key := makeIssueKey(current)
			location := verdictKey{ruleID: key.ruleID, file: key.file, line: key.line, col: key.col, what: key.what}
			entry, ok := byLocation[location]
			if !ok {
				entry = &record{verdicts: make(map[issueKey][]string)}
				byLocation[location] = entry
			}
			entry.verdicts[key] = append(entry.verdicts[key], platform.String())
		}
	}

	conflicts := make([]VerdictConflict, 0)
	for location, entry := range byLocation {
		if len(entry.verdicts) < 2 {
			continue
		}
		conflict := VerdictConflict{
			RuleID: location.ruleID,
			File:   location.file,
			Line:   location.line,
			Column: location.col,
		}
		for verdict, platforms := range entry.verdicts {
			conflict.Verdicts = append(conflict.Verdicts,
				fmt.Sprintf("%s/%s on %s", verdict.severity, verdict.conf, strings.Join(platforms, ",")))
			conflict.Platforms = append(conflict.Platforms, platforms...)
		}
		conflicts = append(conflicts, conflict)
	}
	slices.SortFunc(conflicts, func(a, b VerdictConflict) int {
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		if c := strings.Compare(a.Line, b.Line); c != 0 {
			return c
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})
	return conflicts
}

// reconcile computes the accounting identity for a platform report.
func (r *PlatformReport) reconcile() {
	total := 0
	for _, s := range r.Stats {
		total += s.Issues
	}
	merged := 0
	for _, s := range r.Stats {
		merged += s.Unique
	}
	r.Reconciliation = Reconciliation{
		PerPlatformTotal: total,
		Merged:           merged,
		Duplicates:       total - merged,
		Balanced:         total-merged >= 0,
	}
}

// FilterIssuesByPlatform returns the issues that hit any of the given
// platforms. A filter entry may be a full GOOS/GOARCH pair or a bare GOOS,
// which matches every architecture of that OS. An issue without platform
// information is treated as applying to every platform so that
// single-platform scans are unaffected. An empty platform list returns the
// input unchanged.
func FilterIssuesByPlatform(issues []*issue.Issue, platforms []string) []*issue.Issue {
	if len(platforms) == 0 {
		return issues
	}
	want := make(map[string]bool, len(platforms))
	for _, p := range platforms {
		want[normalizePlatformName(p)] = true
	}
	matches := func(platform string) bool {
		normalized := normalizePlatformName(platform)
		if want[normalized] {
			return true
		}
		if goos, _, found := strings.Cut(normalized, "/"); found {
			return want[goos]
		}
		return false
	}
	filtered := make([]*issue.Issue, 0, len(issues))
	for _, i := range issues {
		if len(i.Platforms) == 0 {
			filtered = append(filtered, i)
			continue
		}
		for _, p := range i.Platforms {
			if matches(p) {
				filtered = append(filtered, i)
				break
			}
		}
	}
	return filtered
}

func normalizePlatformName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// ValidatePlatformReport checks the internal consistency of a platform
// report. It is used by tests and by callers that want to trust the numbers.
func ValidatePlatformReport(report *PlatformReport) error {
	if report == nil {
		return fmt.Errorf("nil platform report")
	}
	unique := 0
	total := 0
	seen := make(map[string]bool)
	for _, s := range report.Stats {
		if seen[s.Platform] {
			return fmt.Errorf("platform %s appears more than once", s.Platform)
		}
		seen[s.Platform] = true
		if s.Unique+s.Duplicates != s.Issues {
			return fmt.Errorf("platform %s: unique(%d)+duplicates(%d) != issues(%d)", s.Platform, s.Unique, s.Duplicates, s.Issues)
		}
		unique += s.Unique
		total += s.Issues
	}
	if report.Reconciliation.PerPlatformTotal != total {
		return fmt.Errorf("per-platform total %d != recorded %d", total, report.Reconciliation.PerPlatformTotal)
	}
	if report.Reconciliation.Merged != unique {
		return fmt.Errorf("merged %d != sum of unique %d", report.Reconciliation.Merged, unique)
	}
	if report.Reconciliation.Duplicates != total-unique {
		return fmt.Errorf("duplicates %d != per-platform total %d - merged %d", report.Reconciliation.Duplicates, total, unique)
	}
	if !report.Reconciliation.Balanced {
		return fmt.Errorf("reconciliation does not balance")
	}
	for _, failure := range report.Failed {
		if !slices.Contains(report.Requested, failure.Platform) {
			return fmt.Errorf("failed platform %s was not requested", failure.Platform)
		}
	}
	return nil
}
