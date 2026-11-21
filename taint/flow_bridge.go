package taint

import (
	"github.com/securego/gosec/v2/taint/flow"
)

// toFlowConfig translates the legacy taint.Config into the flow engine's
// self-contained config. The two types are kept structurally identical in
// meaning but live in separate packages so flow has no import cycle.
func toFlowConfig(cfg *Config) *flow.Config {
	if cfg == nil {
		return &flow.Config{}
	}
	out := &flow.Config{
		Sources:    make([]flow.Source, 0, len(cfg.Sources)),
		Sinks:      make([]flow.Sink, 0, len(cfg.Sinks)),
		Sanitizers: make([]flow.Sanitizer, 0, len(cfg.Sanitizers)),
	}
	for _, s := range cfg.Sources {
		out.Sources = append(out.Sources, flow.Source{
			Package: s.Package,
			Name:    s.Name,
			Pointer: s.Pointer,
			IsFunc:  s.IsFunc,
		})
	}
	for _, s := range cfg.Sinks {
		out.Sinks = append(out.Sinks, flow.Sink{
			Package:       s.Package,
			Receiver:      s.Receiver,
			Method:        s.Method,
			Pointer:       s.Pointer,
			CheckArgs:     append([]int(nil), s.CheckArgs...),
			ArgTypeGuards: copyGuards(s.ArgTypeGuards),
		})
	}
	for _, s := range cfg.Sanitizers {
		out.Sanitizers = append(out.Sanitizers, flow.Sanitizer{
			Package:  s.Package,
			Receiver: s.Receiver,
			Method:   s.Method,
			Pointer:  s.Pointer,
		})
	}
	return out
}

func copyGuards(in map[int]string) map[int]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
