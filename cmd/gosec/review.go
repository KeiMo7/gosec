package main

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/report/review"
)

// maxExcludedDirsListed bounds how many directory names a review report lists
// per exclusion pattern. Totals are always exact; the list is truncated so a
// repository with a huge vendor tree cannot make the header dominate the
// report.
const maxExcludedDirsListed = 50

// toReviewExclusions converts the excluded directory scan results into
// relative, sorted, report-friendly entries.
func toReviewExclusions(excluded []gosec.ExcludedPaths, roots []string) []review.Exclusion {
	type accumulator struct {
		dirs map[string]struct{}
	}
	byPattern := map[string]*accumulator{}
	for _, group := range excluded {
		acc := byPattern[group.Pattern]
		if acc == nil {
			acc = &accumulator{dirs: map[string]struct{}{}}
			byPattern[group.Pattern] = acc
		}
		for _, dir := range group.Dirs {
			acc.dirs[relativizeDir(dir, roots)] = struct{}{}
		}
	}

	patterns := make([]string, 0, len(byPattern))
	for pattern := range byPattern {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)

	out := make([]review.Exclusion, 0, len(patterns))
	for _, pattern := range patterns {
		dirs := make([]string, 0, len(byPattern[pattern].dirs))
		for dir := range byPattern[pattern].dirs {
			dirs = append(dirs, dir)
		}
		sort.Strings(dirs)
		entry := review.Exclusion{Pattern: pattern, Total: len(dirs), Dirs: dirs}
		if len(dirs) > maxExcludedDirsListed {
			entry.Dirs = dirs[:maxExcludedDirsListed]
			entry.Truncated = true
		}
		out = append(out, entry)
	}
	return out
}

func relativizeDir(dir string, roots []string) string {
	clean := filepath.Clean(dir)
	best := ""
	bestLen := -1
	for _, root := range roots {
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(root, clean)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if len(root) > bestLen {
			best, bestLen = rel, len(root)
		}
	}
	if best == "" {
		return filepath.ToSlash(clean)
	}
	return filepath.ToSlash(best)
}
