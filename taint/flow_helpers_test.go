package taint

import (
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"github.com/securego/gosec/v2/internal/ssautil"
)

// buildSSAKey returns the analyzer key gosec uses to store SSA results.
func buildSSAKey() *analysis.Analyzer { return buildssa.Analyzer }

// newSSAInput wraps a buildssa result the way the production analyzer runner
// does, including the shared package-analysis cache for CHA call graphs.
func newSSAInput(result *buildssa.SSA) *ssautil.SSAAnalyzerResult {
	return &ssautil.SSAAnalyzerResult{
		SSA:    result,
		Shared: ssautil.NewPackageAnalysisCache(result),
	}
}
