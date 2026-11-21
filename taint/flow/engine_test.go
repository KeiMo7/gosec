package flow

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"
)

func testConfig() *Config {
	return &Config{
		Sources:    []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:      []Sink{{Package: "p", Method: "Sink"}},
		Sanitizers: []Sanitizer{{Package: "p", Method: "Clean"}},
	}
}

// buildProgram type-checks and builds SSA for a whole in-memory package,
// returning every function (including closures) so concurrency callees are
// present in the analyzed set.
func buildProgram(tb testing.TB, source string) (*ssa.Program, []*ssa.Function, *buildssa.SSA) {
	tb.Helper()
	filename := filepath.Join(tb.TempDir(), "p.go")
	require.NoError(tb, os.WriteFile(filename, []byte(source), 0o600))
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, source, 0)
	require.NoError(tb, err)
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Implicits: make(map[ast.Node]types.Object),
		Scopes: make(map[ast.Node]*types.Scope), Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances: make(map[*ast.Ident]types.Instance),
	}
	var cfg types.Config
	pkg, err := cfg.Check("p", fset, []*ast.File{file}, info)
	require.NoError(tb, err)
	prog := ssa.NewProgram(fset, 0)
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{file}, info, true)
	ssaPkg.Build()
	funcs := allFunctions(prog, ssaPkg)
	return prog, funcs, &buildssa.SSA{Pkg: ssaPkg, SrcFuncs: funcs}
}

func runFlow(t *testing.T, source string) []Finding {
	t.Helper()
	prog, funcs, _ := buildProgram(t, source)
	engine := NewEngine(testConfig())
	return engine.Run(prog, funcs, cha.CallGraph(prog), "test-run")
}

func TestDirectFlowBaseline(t *testing.T) {
	t.Parallel()
	findings := runFlow(t, `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func Producer() { Sink(Source()) }
`)
	require.Len(t, findings, 1)
	require.NotEmpty(t, findings[0].Origins)
	require.NotEmpty(t, findings[0].Trace)
}

func TestChannelForms(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		source    string
		wantTrace string // required trace hop kind; empty only requires a non-empty trace
	}{
		{
			name:      "unbuffered channel to worker goroutine",
			wantTrace: "chan-recv",
			source: `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func Producer() {
	ch := make(chan string)
	go func() { Sink(<-ch) }()
	ch <- Source()
}
`,
		},
		{
			name:      "buffered channel fan-out workers",
			wantTrace: "chan-recv",
			source: `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(ch chan string) { Sink(<-ch) }
func Producer() {
	ch := make(chan string, 3)
	go worker(ch); go worker(ch); go worker(ch)
	ch <- Source()
}
`,
		},
		{
			name:      "fan-in producers one consumer",
			wantTrace: "chan-recv",
			source: `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func producer(ch chan<- string) { ch <- Source() }
func consumer(ch <-chan string) { Sink(<-ch) }
func Producer() {
	ch := make(chan string)
	go producer(ch); go producer(ch); go consumer(ch)
}
`,
		},
		{
			name:      "struct field through channel",
			wantTrace: "chan-recv",
			source: `package p
type Order struct{ ID string }
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(ch chan *Order) { o := <-ch; Sink(o.ID) }
func Producer() {
	ch := make(chan *Order)
	go worker(ch)
	ch <- &Order{ID: Source()}
}
`,
		},
		{
			name:      "slice element through channel",
			wantTrace: "chan-recv",
			source: `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(ch chan []string) { ids := <-ch; Sink(ids[0]) }
func Producer() {
	ch := make(chan []string, 1)
	go worker(ch)
	ch <- []string{Source()}
}
`,
		},
		{
			name:      "map value through channel",
			wantTrace: "chan-recv",
			source: `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(ch chan map[string]string) { m := <-ch; Sink(m["id"]) }
func Producer() {
	ch := make(chan map[string]string, 1)
	go worker(ch)
	ch <- map[string]string{"id": Source()}
}
`,
		},
		{
			name: "interface method return",
			source: `package p
type Carrier interface { Payload() string }
type concrete struct{ v string }
func (c *concrete) Payload() string { return c.v }
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(c Carrier) { Sink(c.Payload()) }
func Producer() { c := &concrete{v: Source()}; go worker(c) }
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := runFlow(t, tc.source)
			require.Len(t, findings, 1, "expected exactly one confirmed flow")
			require.NotEmpty(t, findings[0].Trace, "flow must carry a propagation trace")
			if tc.wantTrace != "" {
				kinds := map[string]bool{}
				for _, node := range findings[0].Trace {
					kinds[node.Kind] = true
				}
				require.True(t, kinds[tc.wantTrace], "trace missing %s hop: %+v", tc.wantTrace, kinds)
			}
		})
	}
}

func TestSanitizerNegativeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		source string
	}{
		{
			name: "sanitizer before the channel",
			source: `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(ch chan string) { Sink(<-ch) }
func Producer() {
	ch := make(chan string, 1)
	go worker(ch)
	ch <- Clean(Source())
}
`,
		},
		{
			name: "sanitizer after the channel on the worker side",
			source: `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(ch chan string) { Sink(Clean(<-ch)) }
func Producer() {
	ch := make(chan string, 1)
	go worker(ch)
	ch <- Source()
}
`,
		},
		{
			name: "constant data through channel",
			source: `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(ch chan string) { Sink(<-ch) }
func Producer() {
	ch := make(chan string, 1)
	go worker(ch)
	ch <- "hardcoded"
}
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := runFlow(t, tc.source)
			require.Empty(t, findings, "sanitized/constant flow must not be reported")
		})
	}
}

func TestDeterministicRepeatedRuns(t *testing.T) {
	t.Parallel()
	source := `package p
func Source() string { return "" }
func Sink(string) {}
func Clean(string) string { return "" }
func worker(ch chan string) { Sink(<-ch) }
func Producer() {
	ch := make(chan string, 1)
	go worker(ch)
	ch <- Source()
}
`
	prog, funcs, _ := buildProgram(t, source)
	var first []Finding
	for i := 0; i < 5; i++ {
		engine := NewEngine(testConfig())
		got := engine.Run(prog, funcs, cha.CallGraph(prog), "run")
		if i == 0 {
			first = got
			continue
		}
		require.Len(t, got, len(first))
		for j := range first {
			require.Equal(t, first[j].SinkPos, got[j].SinkPos)
			require.Equal(t, first[j].SinkDetail, got[j].SinkDetail)
		}
	}
}
