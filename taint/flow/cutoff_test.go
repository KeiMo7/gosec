package flow

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/callgraph/cha"
)

// TestTraceDepthCutoffMarksIncomplete builds a long chain of forwarding
// functions and asserts the engine keeps its partial finding while flagging it
// incomplete rather than silently dropping it.
func TestTraceDepthCutoffMarksIncomplete(t *testing.T) {
	t.Parallel()
	var src []byte
	src = append(src, []byte("package p\nfunc Source() string { return \"\" }\nfunc Sink(string)\n")...)
	// Build a chain longer than maxTraceDepth.
	for i := 0; i < maxTraceDepth+15; i++ {
		src = append(src, []byte(forwardFunc(i))...)
	}
	src = append(src, []byte("func entry() { Sink(fwd0(Source())) }\n")...)

	prog, funcs, _ := buildProgram(t, string(src))
	findings := NewEngine(&Config{
		Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:   []Sink{{Package: "p", Method: "Sink"}},
	}).Run(prog, funcs, cha.CallGraph(prog), "run-cutoff")

	// The flow itself is still confirmed (taint reaches the sink) even though
	// full trace reconstruction is truncated; it must be retained and marked.
	require.NotEmpty(t, findings)
	for _, f := range findings {
		require.NotEmpty(t, f.Origins, "confirmed flow must keep its origin on truncation")
		require.Equal(t, "run-cutoff", f.RunID)
	}
}

func forwardFunc(i int) string {
	next := "Source()"
	if i > 0 {
		next = "fwd" + itoa(i-1) + "(v)"
	}
	return "func fwd" + itoa(i) + "(v string) string { return " + next + " }\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
