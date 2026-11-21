package taint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/taint/flow"
)

// TestFlowWholeProgramSinkCoverage pins the forward engine's whole-program
// semantics: one shared package with several sink calls yields every genuine
// source-to-sink flow, regardless of which function a target parameter names.
func TestFlowWholeProgramSinkCoverage(t *testing.T) {
	t.Parallel()
	const source = `package p
func Source() string { return "" }
func Sink(string) {}
func Other(string) {}
type Writer interface { Write(string) }
type Output struct{}
func (*Output) Write(string) {}
func Sinkless() { Other(Source()) }
func Direct() { Sink(Source()) }
func Forward(value string) { Sink(value) }
func Indirect() { Forward(Source()) }
func Concrete(output *Output) { output.Write(Source()) }
func Dynamic(output Writer) { output.Write(Source()) }
func Closure() { f := func() { Sink(Source()) }; f() }
func Constant() { Sink("safe") }
`
	_, result := sinkPrecheckPass(t, source, "Direct")
	pass, _ := sinkPrecheckPass(t, source, "Direct")
	input := newSSAInput(result)
	pass.ResultOf[buildSSAKey()] = input

	cfg := &Config{
		Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:   []Sink{{Package: "p", Method: "Sink"}},
	}
	runner := NewGosecAnalyzer(&RuleInfo{ID: "G701", Description: "test sink", Severity: "HIGH"}, cfg)
	value, err := runner.Run(pass)
	require.NoError(t, err)

	issues, ok := value.([]*issue.Issue)
	require.True(t, ok)
	// Genuine Sink flows: Direct, Indirect (via Forward), Closure.
	// Sinkless has no Sink; Constant passes a literal; neither may appear.
	require.Len(t, issues, 3)
	for _, iss := range issues {
		assert.Equal(t, "G701", iss.RuleID)
		assert.NotEmpty(t, iss.What)
	}
}

// TestFlowInterfaceSinkWholeProgram covers the method-form sink in the same
// whole-program setting, including its CHA-resolved dynamic implementation.
func TestFlowInterfaceSinkWholeProgram(t *testing.T) {
	t.Parallel()
	const source = `package p
type Writer interface { Write(string) }
type Output struct{}
func (*Output) Write(string) {}
func Source() string { return "" }
func Dynamic(output Writer) { output.Write(Source()) }
func Safe(output Writer) { output.Write("literal") }
`
	pass, result := sinkPrecheckPass(t, source, "Dynamic")
	pass.ResultOf[buildSSAKey()] = newSSAInput(result)
	cfg := &Config{
		Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:   []Sink{{Package: "p", Receiver: "Writer", Method: "Write"}},
	}
	value, err := NewGosecAnalyzer(&RuleInfo{ID: "G701", Description: "t", Severity: "HIGH"}, cfg).Run(pass)
	require.NoError(t, err)
	issues, ok := value.([]*issue.Issue)
	require.True(t, ok)
	require.Len(t, issues, 1, "only the tainted dynamic Write must be reported")
}

var _ = flow.ConfidenceHigh
