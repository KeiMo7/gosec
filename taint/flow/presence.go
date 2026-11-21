package flow

import (
	"golang.org/x/tools/go/ssa"
)

// hasAnySink reports whether any function contains a call matching a
// configured sink. It is the flow engine's equivalent of the legacy
// hasSinkCalls precheck, used to skip call-graph work on sink-free packages.
func hasAnySink(funcs []*ssa.Function, cfg *Config) bool {
	rules := BuildRules(cfg)
	for _, fn := range funcs {
		if fn == nil || fn.Blocks == nil {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				call, ok := instr.(*ssa.Call)
				if !ok {
					continue
				}
				if _, isSink := rules.matchSink(call); isSink {
					return true
				}
			}
		}
	}
	return false
}
