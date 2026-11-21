package flow

import (
	"go/token"
	"go/types"
	"sort"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// interprocedural connects call sites to callee bodies, goroutine entries to
// their spawn sites, closures to their bound free variables and interface
// invokes to every CHA-resolved implementation.
type interprocedural struct {
	b        *builder
	cg       *callgraph.Graph
	analyzed map[*ssa.Function]bool
	// dispatch maps a dynamic call-site position to its sorted CHA callees,
	// built once so each invoke is an O(1) lookup instead of a graph scan.
	dispatch map[token.Pos][]*ssa.Function
}

// buildInterprocedural emits all cross-function edges for the analyzed set.
func (b *builder) buildInterprocedural(funcs []*ssa.Function, cg *callgraph.Graph) {
	ip := &interprocedural{
		b:        b,
		cg:       cg,
		analyzed: make(map[*ssa.Function]bool, len(funcs)),
		dispatch: make(map[token.Pos][]*ssa.Function),
	}
	for _, fn := range funcs {
		ip.analyzed[fn] = true
	}
	ip.indexDispatch()
	// Deterministic outer order: functions by their origin position.
	for _, fn := range sortedFuncs(funcs) {
		ip.scanCalls(fn)
	}
}

// indexDispatch collects every CHA edge whose site is a dynamic dispatch and
// groups its callees by the site position.
func (ip *interprocedural) indexDispatch() {
	if ip.cg == nil {
		return
	}
	seen := make(map[token.Pos]map[*ssa.Function]bool)
	for _, node := range ip.cg.Nodes {
		for _, e := range node.Out {
			if e.Site == nil || e.Callee == nil || e.Callee.Func == nil {
				continue
			}
			common := e.Site.Common()
			if common == nil || common.StaticCallee() != nil {
				continue // static calls are resolved directly
			}
			pos := e.Site.Pos()
			if seen[pos] == nil {
				seen[pos] = make(map[*ssa.Function]bool)
			}
			if !seen[pos][e.Callee.Func] {
				seen[pos][e.Callee.Func] = true
				ip.dispatch[pos] = append(ip.dispatch[pos], e.Callee.Func)
			}
		}
	}
	for pos, funcs := range ip.dispatch {
		ip.dispatch[pos] = sortedFuncs(funcs)
	}
}

func (ip *interprocedural) scanCalls(fn *ssa.Function) {
	if fn.Blocks == nil {
		return
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			switch site := instr.(type) {
			case *ssa.Call:
				ip.connectCall(fn, site, false)
			case *ssa.Go:
				ip.connectGo(fn, site)
			case *ssa.Defer:
				// A deferred call runs in the same goroutine but after the
				// surrounding function; data flow is identical to a normal call.
				ip.connectDefer(fn, site)
			}
		}
	}
}

// connectCall maps caller arguments onto callee parameters and callee return
// values onto the call result.
func (ip *interprocedural) connectCall(fn *ssa.Function, call *ssa.Call, spawned bool) {
	callees := ip.resolveCallees(call)
	if len(callees) == 0 {
		return
	}
	for _, callee := range callees {
		ip.bindCall(call, callee, spawned, call)
	}
}

func (ip *interprocedural) connectGo(fn *ssa.Function, goInstr *ssa.Go) {
	// A goroutine spawn is a call whose callee executes concurrently. Connect
	// arguments exactly like a synchronous call: the channel/region model
	// carries the actual inter-goroutine data, while direct argument passing
	// (go worker(ch)) must not break the chain either.
	callees := ip.resolveCalleesGo(goInstr)
	for _, callee := range callees {
		ip.bindCommon(&goInstr.Call, callee, true, goInstr)
	}
}

func (ip *interprocedural) connectDefer(fn *ssa.Function, deferInstr *ssa.Defer) {
	callees := ip.resolveCalleesDefer(deferInstr)
	for _, callee := range callees {
		ip.bindCommon(&deferInstr.Call, callee, false, deferInstr)
	}
}

// resolveCallees returns every concrete callee a call may dispatch to.
// Static callees return one entry; interface invokes use CHA for soundness.
func (ip *interprocedural) resolveCallees(call *ssa.Call) []*ssa.Function {
	if callee := call.Call.StaticCallee(); callee != nil {
		return []*ssa.Function{callee}
	}
	return ip.dynamicCallees(call.Common())
}

func (ip *interprocedural) resolveCalleesGo(goInstr *ssa.Go) []*ssa.Function {
	if callee := goInstr.Call.StaticCallee(); callee != nil {
		return []*ssa.Function{callee}
	}
	return ip.dynamicCallees(&goInstr.Call)
}

func (ip *interprocedural) resolveCalleesDefer(deferInstr *ssa.Defer) []*ssa.Function {
	if callee := deferInstr.Call.StaticCallee(); callee != nil {
		return []*ssa.Function{callee}
	}
	return ip.dynamicCallees(&deferInstr.Call)
}

// dynamicCallees resolves an interface invoke or function-value call via the
// precomputed CHA dispatch index.
func (ip *interprocedural) dynamicCallees(common *ssa.CallCommon) []*ssa.Function {
	if ip.cg == nil {
		return nil
	}
	return ip.dispatch[common.Pos()]
}

// bindCall wires a synchronous call including its return values.
func (ip *interprocedural) bindCall(call *ssa.Call, callee *ssa.Function, spawned bool, site ssa.Instruction) {
	ip.bindCommon(call.Common(), callee, spawned, site)
	// Return edges are only modeled for functions inside the analysis package.
	// External/dependency callees are handled opaquely by scanCall, which
	// conservatively connects their data-carrying arguments to the result.
	if callee.Blocks == nil || !ip.b.inAnalysisUnit(callee) {
		return
	}
	// Return values -> call result. Single-return calls produce an ssa.Call
	// value; multi-return calls produce a tuple unpacked by Extract.
	for _, block := range callee.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			for i, rv := range ret.Results {
				// A reference-typed return (pointer/slice/map/chan/interface)
				// names one runtime object on both sides of the call, so unify
				// the callee's returned object with the caller's result. This
				// makes content (struct fields, elements) allocated in the
				// callee reachable at the call site.
				if isReferenceType(rv.Type()) {
					ip.b.uf.union(rv, call)
				}
				tag := "return"
				if i != 0 {
					tag = "return-tuple"
				}
				ip.b.addEdge(edgeCallReturn, ip.b.ls.locForValue(rv), ip.b.ls.locForValue(call), ret, tag)
			}
		}
	}
}

// bindCommon maps call arguments (receiver included at index 0) onto callee
// parameters. spawned marks a goroutine entry. site is the inducing
// instruction for trace reconstruction.
func (ip *interprocedural) bindCommon(common *ssa.CallCommon, callee *ssa.Function, spawned bool, site ssa.Instruction) {
	tag := "call"
	if spawned {
		tag = "go"
	}

	// Interface invokes keep the receiver in common.Value while Args holds
	// only non-receiver arguments; callee.Params still starts with the
	// receiver. Align the two explicitly so the receiver parameter is unified
	// with the concrete/interface value dispatched on.
	argIndex := 0
	if common.IsInvoke() && len(callee.Params) > 0 {
		recv := callee.Params[0]
		if common.Value != nil {
			if isReferenceType(common.Value.Type()) {
				ip.b.uf.union(common.Value, recv)
			}
			ip.b.addEdge(edgeCallArg, ip.b.ls.locForValue(common.Value), ip.b.ls.locForValue(recv), site, tag+"-recv")
		}
		argIndex = 1
	}

	for _, arg := range common.Args {
		if argIndex >= len(callee.Params) {
			break
		}
		param := callee.Params[argIndex]
		// A function argument (method value / callback) carries no data itself;
		// its captured free variables are already bound at MakeClosure.
		if _, isFunc := arg.Type().(*types.Signature); isFunc {
			argIndex++
			continue
		}
		if isContext(arg.Type()) {
			argIndex++
			continue
		}
		// Reference-like arguments name the same runtime object on both sides
		// of the call. Unify them so channels, maps, slices and structs passed
		// into a worker function keep a single canonical region.
		if isReferenceType(arg.Type()) {
			ip.b.uf.union(arg, param)
		}
		// Variadic parameter: the caller's arguments are packed into a slice.
		// Connect each variadic argument into the parameter slice's element
		// region so a value passed positionally (e.g. fmt.Sprintf("...", id))
		// stays reachable when the callee indexes its variadic slice.
		if ip.isVariadicParam(callee, argIndex) {
			ip.b.addRegionEdge(edgeCallArg, vLoc(arg), rLoc(locIndex, param, 0), site, tag+"-variadic")
		}
		// Bind argument to parameter. This applies even to external functions
		// (no body), because a sink reads its parameter directly: the sink
		// evaluator inspects the call argument location, and this edge makes
		// sure taint reaches it through any wrapper/forwarder.
		ip.b.addEdge(edgeCallArg, ip.b.ls.locForValue(arg), ip.b.ls.locForValue(param), site, tag)
		argIndex++
	}
}

// isVariadicParam reports whether parameter index idx is the final variadic
// slice parameter of callee.
func (ip *interprocedural) isVariadicParam(callee *ssa.Function, idx int) bool {
	if callee == nil || callee.Signature == nil {
		return false
	}
	sig := callee.Signature
	if !sig.Variadic() {
		return false
	}
	return idx == len(callee.Params)-1
}

// sortedFuncs orders functions by (package path, name, position) for stable
// edge insertion.
func sortedFuncs(funcs []*ssa.Function) []*ssa.Function {
	out := append([]*ssa.Function(nil), funcs...)
	sortFuncsByPos(out)
	return out
}

func sortFuncsByPos(out []*ssa.Function) {
	sort.SliceStable(out, func(i, j int) bool {
		pa, pb := funcKey(out[i]), funcKey(out[j])
		if pa != pb {
			return pa < pb
		}
		return out[i].Pos() < out[j].Pos()
	})
}

func funcKey(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg.Path() + "." + fn.Name()
	}
	return fn.Name()
}
