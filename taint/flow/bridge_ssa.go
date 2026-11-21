package flow

import (
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

// buildSSAAnalyzer returns the buildssa analyzer reference. gosec constructs
// the pass result itself (see internal/ssautil), so this only satisfies the
// analysis.Analyzer.Requires contract.
func buildSSAAnalyzer() *analysis.Analyzer {
	return buildssa.Analyzer
}
