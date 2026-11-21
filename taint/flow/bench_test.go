package flow

import (
	"testing"

	"golang.org/x/tools/go/callgraph/cha"
)

// BenchmarkFlowEngine measures the forward fixed-point engine on a package
// with mixed direct, channel and function-call flows. It guards the hard
// performance constraint: the whole-program analysis must stay within the
// agreed time budget relative to the per-package demand-driven engine.
func BenchmarkFlowEngine(b *testing.B) {
	source := stressSource(180)
	prog, funcs, _ := buildProgram(b, source)
	cfg := &Config{
		Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
		Sinks:   []Sink{{Package: "p", Method: "Sink"}},
	}
	cg := cha.CallGraph(prog)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		eng := NewEngine(cfg)
		if got := eng.Run(prog, funcs, cg, "bench"); len(got) == 0 {
			b.Fatal("expected findings on stress program")
		}
	}
}

func stressSource(n int) string {
	var out []byte
	out = append(out, []byte("package p\nfunc Source() string { return \"\" }\nfunc Sink(string)\n")...)
	out = append(out, []byte("func worker(ch chan string) { Sink(<-ch) }\n")...)
	for i := 0; i < n; i++ {
		out = append(out, []byte(
			"func h"+itoa(i)+"(ch chan string) {\n"+
				"  v := Source()\n"+
				"  go worker(ch)\n"+
				"  ch <- v\n"+
				"}\n")...)
	}
	return string(out)
}
