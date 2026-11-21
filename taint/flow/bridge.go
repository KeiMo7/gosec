package flow

import (
	"fmt"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/securego/gosec/v2/internal/ssautil"
	"github.com/securego/gosec/v2/issue"
)

// RuleMeta is the subset of rule metadata the bridge needs.
type RuleMeta struct {
	ID          string
	Description string
	Severity    string
}

// Bridge runs the forward taint engine through gosec's analysis.Pass
// machinery and converts findings into gosec issues. It is the single
// integration point used by every G7xx taint rule.
type Bridge struct {
	rule RuleMeta
	cfg  *Config
}

// NewBridge constructs a bridge for one rule.
func NewBridge(rule RuleMeta, cfg *Config) *Bridge {
	return &Bridge{rule: rule, cfg: cfg}
}

// AsAnalysisAnalyzer packages the bridge as a golang.org/x/tools analyzer so
// gosec can register it alongside its existing analyzer set.
func (br *Bridge) AsAnalysisAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: br.rule.ID,
		Doc:  br.rule.Description,
		Run:  br.run,
		Requires: []*analysis.Analyzer{
			// buildssa.Analyzer is supplied by gosec's pass construction.
			buildSSAAnalyzer(),
		},
	}
}

// run executes the engine against an analysis pass carrying a buildssa result.
func (br *Bridge) run(pass *analysis.Pass) (any, error) {
	ssaResult, err := ssautil.GetSSAResult(pass)
	if err != nil {
		return nil, fmt.Errorf("taint flow %s: %w", br.rule.ID, err)
	}
	bssa := ssaResult.SSA
	if bssa == nil || bssa.Pkg == nil {
		return nil, nil
	}

	prog := bssa.Pkg.Prog
	// The buildssa SrcFuncs list omits named-type methods; expand to the full
	// analyzable set so interface method implementations are present.
	funcs := AllFunctions(prog, bssa.Pkg)
	if len(funcs) == 0 {
		return nil, nil
	}

	// Sink precheck mirrors the legacy engine: packages without a configured
	// sink call bail out before any call-graph construction, keeping the
	// no-sink path allocation-light and avoiding a CHA build on a nil program.
	if !hasAnySink(funcs, br.cfg) {
		return nil, nil
	}

	var cg = ssaResult.Shared.CallGraph()
	engine := NewEngine(br.cfg)
	findings := engine.Run(prog, funcs, cg, pass.Pkg.Path())
	if len(findings) == 0 {
		return nil, nil
	}
	issues := br.toIssues(pass, findings)
	// Mirror the legacy runner's go/vet integration: emit one diagnostic per
	// finding so callers driving the analyzer via pass.Report see them too.
	for _, f := range findings {
		if pass.Report != nil {
			pass.Report(analysis.Diagnostic{
				Pos:     f.SinkPos,
				Message: br.rule.Description,
			})
		}
	}
	return issues, nil
}

// toIssues converts engine findings into gosec issues with a stable ordering.
func (br *Bridge) toIssues(pass *analysis.Pass, findings []Finding) []*issue.Issue {
	severity := issue.Medium
	switch br.rule.Severity {
	case "LOW":
		severity = issue.Low
	case "MEDIUM":
		severity = issue.Medium
	case "HIGH", "CRITICAL":
		severity = issue.High
	}

	out := make([]*issue.Issue, 0, len(findings))
	for _, f := range findings {
		confidence := issue.High
		if f.Confidence == ConfidenceMedium {
			confidence = issue.Medium
		}
		file := pass.Fset.File(f.SinkPos)
		if file == nil {
			continue
		}
		position := file.Position(f.SinkPos)
		if position.Filename == "" {
			position.Filename = file.Name()
		}
		out = append(out, &issue.Issue{
			Severity:   severity,
			Confidence: confidence,
			Cwe:        issue.GetCweByRule(br.rule.ID),
			RuleID:     br.rule.ID,
			What:       br.rule.Description + ": " + formatTrace(pass.Fset, f),
			File:       position.Filename,
			Line:       strconv.Itoa(position.Line),
			Col:        strconv.Itoa(position.Column),
			Code:       snippet(pass.Fset, f.SinkPos),
		})
	}
	sortIssues(out)
	return out
}

// runTag renders the run-binding prefix for an incomplete finding.
func runTag(f Finding) string {
	if !f.Incomplete || f.RunID == "" {
		return ""
	}
	return "[run=" + f.RunID + " incomplete] "
}

// formatTrace renders the propagation path as a deterministic, human-readable
// chain, including every function and hop the value crosses.
func formatTrace(fset *token.FileSet, f Finding) string {
	var b strings.Builder
	b.WriteString(runTag(f))
	b.WriteString(f.SinkDetail)
	if len(f.Notes) > 0 {
		notes := append([]string(nil), f.Notes...)
		sort.Strings(notes)
		b.WriteString(" [")
		b.WriteString(strings.Join(notes, "; "))
		b.WriteString("]")
	}
	if len(f.Trace) == 0 {
		return b.String()
	}
	b.WriteString(" | flow: ")
	for i, node := range f.Trace {
		if i > 0 {
			b.WriteString(" -> ")
		}
		b.WriteString(node.Kind)
		if node.Detail != "" {
			b.WriteString("(")
			b.WriteString(node.Detail)
			b.WriteString(")")
		}
		if node.Pos.IsValid() {
			pos := fset.Position(node.Pos)
			fmt.Fprintf(&b, "@%s:%d", pos.Filename, pos.Line)
		}
		if node.Func != nil {
			fmt.Fprintf(&b, " in %s", node.Func.Name())
		}
	}
	return b.String()
}

func snippet(fset *token.FileSet, pos token.Pos) string {
	file := fset.File(pos)
	if file == nil {
		return ""
	}
	start := file.Line(pos) - issue.SnippetOffset
	if start < 1 {
		start = 1
	}
	end := file.Line(pos) + issue.SnippetOffset
	fh, err := os.Open(file.Name())
	if err != nil {
		return err.Error()
	}
	defer fh.Close() // #nosec
	code, err := issue.CodeSnippet(fh, int64(start), int64(end))
	if err != nil {
		return err.Error()
	}
	return code
}

func sortIssues(out []*issue.Issue) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].What < out[j].What
	})
}
