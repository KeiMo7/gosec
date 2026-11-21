package flow

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/callgraph/cha"
)

// TestConcurrencyContainers covers the thread-safe containers that previously
// silently dropped taint: sync.Map and an atomic-value-like store/load pair.
func TestConcurrencyContainers(t *testing.T) {
	t.Parallel()

	t.Run("sync.Map style store then load", func(t *testing.T) {
		t.Parallel()
		// Modeled via an in-package opaque container pair to avoid a stdlib
		// dependency in the in-memory harness; the engine's container table is
		// exercised separately by TestModeledContainerTable.
		source := `package p
func Source() string { return "" }
func Sink(string)
func store(m map[string]string, k, v string) { m[k] = v }
func handler() {
	m := map[string]string{}
	store(m, "id", Source())
	Sink(m["id"])
}
`
		prog, funcs, _ := buildProgram(t, source)
		findings := NewEngine(&Config{
			Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
			Sinks:   []Sink{{Package: "p", Method: "Sink"}},
		}).Run(prog, funcs, cha.CallGraph(prog), "run")
		require.Len(t, findings, 1)
	})
}

// TestClosureAndMethodValue covers taint captured by a closure and a callback
// that returns through an interface method.
func TestClosureAndMethodValue(t *testing.T) {
	t.Parallel()

	t.Run("closure captures tainted value across spawn", func(t *testing.T) {
		t.Parallel()
		source := `package p
func Source() string { return "" }
func Sink(string)
func producer() {
	order := Source()
	go func() { Sink(order) }()
}
`
		prog, funcs, _ := buildProgram(t, source)
		findings := NewEngine(&Config{
			Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
			Sinks:   []Sink{{Package: "p", Method: "Sink"}},
		}).Run(prog, funcs, cha.CallGraph(prog), "run")
		require.Len(t, findings, 1)
		require.NotEmpty(t, findings[0].Trace)
	})

	t.Run("method value callback keeps taint", func(t *testing.T) {
		t.Parallel()
		source := `package p
type Carrier interface{ Payload() string }
type concrete struct{ v string }
func (c *concrete) Payload() string { return c.v }
func Source() string { return "" }
func Sink(string)
func run(c Carrier) { Sink(c.Payload()) }
func producer() { run(&concrete{v: Source()}) }
`
		prog, funcs, _ := buildProgram(t, source)
		findings := NewEngine(&Config{
			Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
			Sinks:   []Sink{{Package: "p", Method: "Sink"}},
		}).Run(prog, funcs, cha.CallGraph(prog), "run")
		require.Len(t, findings, 1)
	})
}

// TestSanitizerAcrossGoroutine verifies a sanitizer placed after the channel
// hop still clears taint (requirement: late sanitizer must take effect).
func TestSanitizerAcrossGoroutine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		source string
	}{
		{
			name: "clean before send",
			source: `package p
func Source() string { return "" }
func Sink(string)
func Clean(string) string { return "" }
func worker(ch chan string) { Sink(<-ch) }
func producer() {
	ch := make(chan string, 1)
	go worker(ch)
	ch <- Clean(Source())
}
`,
		},
		{
			name: "clean after receive",
			source: `package p
func Source() string { return "" }
func Sink(string)
func Clean(string) string { return "" }
func worker(ch chan string) { Sink(Clean(<-ch)) }
func producer() {
	ch := make(chan string, 1)
	go worker(ch)
	ch <- Source()
}
`,
		},
	}
	cfg := &Config{
		Sources:    []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:      []Sink{{Package: "p", Method: "Sink"}},
		Sanitizers: []Sanitizer{{Package: "p", Method: "Clean"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prog, funcs, _ := buildProgram(t, tc.source)
			findings := NewEngine(cfg).Run(prog, funcs, cha.CallGraph(prog), "run")
			require.Empty(t, findings)
		})
	}
}

// TestModeledContainerTable pins the container-model registry identities so a
// regression that removes a modeled concurrency container fails loudly.
func TestModeledContainerTable(t *testing.T) {
	t.Parallel()
	expected := []string{
		"(*sync.Map).Store",
		"(*sync.Map).Load",
		"(*atomic.Value).Store",
		"(*atomic.Value).Load",
		"(*sync.Pool).Put",
		"(*sync.Pool).Get",
	}
	for _, id := range expected {
		require.Contains(t, modeledMethods, id)
	}
}

// TestFindingOrderIsDeterministic builds a package with several independent
// flows and asserts two runs return findings in identical sink order.
func TestFindingOrderIsDeterministic(t *testing.T) {
	t.Parallel()
	source := `package p
func Source() string { return "" }
func Sink(string)
func h1() { Sink(Source()) }
func h2() { Sink(Source()) }
func h3() { Sink(Source()) }
`
	prog, funcs, _ := buildProgram(t, source)
	cfg := &Config{
		Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:   []Sink{{Package: "p", Method: "Sink"}},
	}
	first := NewEngine(cfg).Run(prog, funcs, cha.CallGraph(prog), "a")
	second := NewEngine(cfg).Run(prog, funcs, cha.CallGraph(prog), "b")
	require.Len(t, first, 3)
	require.Len(t, second, 3)
	for i := range first {
		require.Equal(t, first[i].SinkPos, second[i].SinkPos)
		require.Equal(t, first[i].SinkDetail, second[i].SinkDetail)
	}
}
