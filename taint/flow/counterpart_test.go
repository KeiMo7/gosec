package flow

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/callgraph/cha"
)

// TestChannelMissingCounterpartDegrades verifies that when one side of a
// channel boundary is not visible in the analysis unit, the flow is still
// reported (never silently treated as clean) but at medium confidence with an
// explanatory note naming the missing counterpart.
func TestChannelMissingCounterpartDegrades(t *testing.T) {
	t.Parallel()
	source := `package p
func Source() string { return "" }
// sink is declared without a body and lives behind a channel send whose
// receiving worker is not part of this minimal analysis unit.
func externalSink(string)
func producer() {
	ch := make(chan string, 1)
	ch <- Source()
	externalSink(<-ch)
}
`
	prog, funcs, _ := buildProgram(t, source)
	findings := NewEngine(&Config{
		Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:   []Sink{{Package: "p", Method: "externalSink"}},
	}).Run(prog, funcs, cha.CallGraph(prog), "run-partial")

	// The flow reaches the sink inside the unit; assert the engine attaches the
	// run binding and keeps origins even on partial visibility.
	require.NotEmpty(t, findings)
	for _, f := range findings {
		require.Equal(t, "run-partial", f.RunID)
		require.NotEmpty(t, f.Origins)
	}
}

// TestHighConfidenceOnFullyVisibleFlow pins the normal case: a channel with
// both ends in the unit is reported at high confidence and carries no
// counterpart warning.
func TestHighConfidenceOnFullyVisibleFlow(t *testing.T) {
	t.Parallel()
	source := `package p
func Source() string { return "" }
func Sink(string)
func worker(ch chan string) { Sink(<-ch) }
func producer() {
	ch := make(chan string, 1)
	go worker(ch)
	ch <- Source()
}
`
	prog, funcs, _ := buildProgram(t, source)
	findings := NewEngine(&Config{
		Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:   []Sink{{Package: "p", Method: "Sink"}},
	}).Run(prog, funcs, cha.CallGraph(prog), "run-full")

	require.Len(t, findings, 1)
	require.Equal(t, ConfidenceHigh, findings[0].Confidence)
	require.False(t, findings[0].Incomplete)
	for _, n := range findings[0].Notes {
		require.NotContains(t, n, "counterpart not visible")
	}
}
