package flow

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// Source describes where tainted data originates. It mirrors the parent taint
// package's Source so flow stays import-cycle-free.
type Source struct {
	Package string
	Name    string
	Pointer bool
	IsFunc  bool
}

// Sink describes a dangerous call that must not receive tainted data.
type Sink struct {
	Package       string
	Receiver      string
	Method        string
	Pointer       bool
	CheckArgs     []int
	ArgTypeGuards map[int]string
}

// Sanitizer describes a call that neutralizes taint.
type Sanitizer struct {
	Package  string
	Receiver string
	Method   string
	Pointer  bool
}

// Config is the flow engine's rule configuration.
type Config struct {
	Sources    []Source
	Sinks      []Sink
	Sanitizers []Sanitizer
}

// RuleSet is the resolved, lookup-oriented view of a Config.
type RuleSet struct {
	typeSources map[string]struct{} // "pkg.Name" / "*pkg.Name"
	funcSources map[string]struct{} // "pkg.Func"
	globalSrcs  map[string]struct{} // "pkg.Var"
	sinks       map[string]sinkSpec
	sanitizers  map[string]struct{}
}

type sinkSpec struct {
	spec       Sink
	argIndices []int
}

// BuildRules converts a Config into an indexed RuleSet.
func BuildRules(cfg *Config) *RuleSet {
	r := &RuleSet{
		typeSources: make(map[string]struct{}),
		funcSources: make(map[string]struct{}),
		globalSrcs:  make(map[string]struct{}),
		sinks:       make(map[string]sinkSpec),
		sanitizers:  make(map[string]struct{}),
	}
	for _, s := range cfg.Sources {
		key := s.Package + "." + s.Name
		if s.Pointer {
			key = "*" + key
		}
		r.typeSources[key] = struct{}{}
		if s.IsFunc {
			r.funcSources[s.Package+"."+s.Name] = struct{}{}
			r.globalSrcs[key] = struct{}{}
		}
	}
	for _, sk := range cfg.Sinks {
		r.sinks[sinkKey(sk.Package, sk.Receiver, sk.Method, sk.Pointer)] = sinkSpec{
			spec:       sk,
			argIndices: append([]int(nil), sk.CheckArgs...),
		}
	}
	for _, san := range cfg.Sanitizers {
		r.sanitizers[sinkKey(san.Package, san.Receiver, san.Method, san.Pointer)] = struct{}{}
	}
	return r
}

func sinkKey(pkg, recv, method string, pointer bool) string {
	if recv == "" {
		return pkg + "." + method
	}
	r := pkg + "." + recv
	if pointer {
		r = "*" + r
	}
	return "(" + r + ")." + method
}

// isTypeSource reports whether t is a configured source type (unwrapping
// pointers and named types the same way the legacy engine does).
func (r *RuleSet) isTypeSource(t types.Type) bool {
	if t == nil {
		return false
	}
	if _, ok := r.typeSources[t.String()]; ok {
		return true
	}
	for {
		ptr, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		obj := named.Obj()
		if obj != nil && obj.Pkg() != nil {
			key := obj.Pkg().Path() + "." + obj.Name()
			if _, ok := r.typeSources[key]; ok {
				return true
			}
			if _, ok := r.typeSources["*"+key]; ok {
				return true
			}
		}
	}
	return false
}

// funcIdentity returns "pkg.Func" for a statically known function.
func funcIdentity(fn *ssa.Function) string {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return ""
	}
	return fn.Pkg.Pkg.Path() + "." + fn.Name()
}

// isSourceFunc reports whether a static callee is a configured function source.
func (r *RuleSet) isSourceFunc(call *ssa.Call) bool {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return false
	}
	_, ok := r.funcSources[funcIdentity(callee)]
	return ok
}

// matchSink resolves a call instruction to a configured sink.
func (r *RuleSet) matchSink(call *ssa.Call) (sinkSpec, bool) {
	if call.Call.IsInvoke() {
		if named, ok := call.Call.Value.Type().(*types.Named); ok {
			pkg, recv := "", named.Obj().Name()
			if obj := named.Obj(); obj != nil && obj.Pkg() != nil {
				pkg = obj.Pkg().Path()
			}
			if spec, ok := r.sinks[sinkKey(pkg, recv, call.Call.Method.Name(), false)]; ok {
				return spec, true
			}
		}
		return sinkSpec{}, false
	}
	callee := call.Call.StaticCallee()
	if callee == nil {
		return sinkSpec{}, false
	}
	pkg, recv, pointer := "", "", false
	if callee.Pkg != nil && callee.Pkg.Pkg != nil {
		pkg = callee.Pkg.Pkg.Path()
	}
	if recvSig := callee.Signature.Recv(); recvSig != nil {
		switch rt := recvSig.Type().(type) {
		case *types.Named:
			recv = rt.Obj().Name()
		case *types.Pointer:
			pointer = true
			if named, ok := rt.Elem().(*types.Named); ok {
				recv = named.Obj().Name()
			}
		}
	}
	spec, ok := r.sinks[sinkKey(pkg, recv, callee.Name(), pointer)]
	return spec, ok
}

// isSanitizer reports whether a static callee is configured as a sanitizer.
func (r *RuleSet) isSanitizer(call *ssa.Call) bool {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return false
	}
	pkg, recv, pointer := "", "", false
	if callee.Pkg != nil && callee.Pkg.Pkg != nil {
		pkg = callee.Pkg.Pkg.Path()
	}
	if recvSig := callee.Signature.Recv(); recvSig != nil {
		switch rt := recvSig.Type().(type) {
		case *types.Named:
			recv = rt.Obj().Name()
		case *types.Pointer:
			pointer = true
			if named, ok := rt.Elem().(*types.Named); ok {
				recv = named.Obj().Name()
			}
		}
	}
	_, ok := r.sanitizers[sinkKey(pkg, recv, callee.Name(), pointer)]
	return ok
}

// argsToCheck maps a sink spec and a concrete call to the argument positions
// that must be inspected for taint.
func (s sinkSpec) argsToCheck(call *ssa.Call) []ssa.Value {
	args := call.Call.Args
	if len(s.argIndices) == 0 {
		return args
	}
	out := make([]ssa.Value, 0, len(s.argIndices))
	for _, idx := range s.argIndices {
		if idx < len(args) {
			out = append(out, args[idx])
		}
	}
	return out
}
