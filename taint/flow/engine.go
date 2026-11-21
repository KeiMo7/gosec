package flow

import (
	"go/token"
	"go/types"
	"sort"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// maxFixedPointIterations bounds the worklist drain. Inclusion constraints
// converge monotonically; this cap only guards against pathological cycles.
// When hit, the engine keeps the partial result and records an incomplete note
// instead of silently treating remaining locations as clean.
const maxFixedPointIterations = 2_000_000

// Engine runs the forward fixed-point taint analysis over an SSA program.
type Engine struct {
	prog    *ssa.Program
	rules   *RuleSet
	b       *builder
	cg      *callgraph.Graph
	origins map[Loc][]Origin
	// tainted[loc] is the set of origin IDs reaching that location.
	tainted map[int]map[int]struct{}
	// incoming is the reverse adjacency used by the worklist.
	incoming map[int][]Edge
	// outCache memoizes forward adjacency derived from incoming.
	outCache map[int][]Edge
	notes    []string
	cutoff   bool
	runID    string
}

// NewEngine constructs an engine from a flow config.
func NewEngine(cfg *Config) *Engine {
	return &Engine{
		rules:    BuildRules(cfg),
		origins:  make(map[Loc][]Origin),
		tainted:  make(map[int]map[int]struct{}),
		incoming: make(map[int][]Edge),
	}
}

// Run builds edges, seeds origins and drains the worklist. funcs is the
// analyzed function set (the package's SrcFuncs plus closures).
func (e *Engine) Run(prog *ssa.Program, funcs []*ssa.Function, cg *callgraph.Graph, runID string) []Finding {
	e.prog = prog
	e.cg = cg
	e.runID = runID

	e.b = newBuilder(e.rules)
	e.b.setAnalyzed(funcs)
	for _, fn := range funcs {
		e.b.scanFunction(fn)
	}
	e.b.buildInterprocedural(funcs, cg)
	e.b.materialize()

	e.buildReverseGraph()
	e.seedOrigins(funcs)
	e.solve()

	return e.collectFindings(funcs)
}

// buildReverseGraph indexes edges by destination, removing exact duplicates so
// repeated stores through the same region cannot inflate work or traces.
func (e *Engine) buildReverseGraph() {
	type edgeKey struct {
		kind     edgeKind
		from, to int
		tag      string
	}
	seen := make(map[edgeKey]bool)
	for _, ed := range e.b.edges {
		key := edgeKey{ed.kind, ed.from.id, ed.to.id, ed.tag}
		if seen[key] {
			continue
		}
		seen[key] = true
		e.incoming[ed.to.id] = append(e.incoming[ed.to.id], ed)
	}
	// Deterministic edge order at every destination.
	for to := range e.incoming {
		edges := e.incoming[to]
		sort.SliceStable(edges, func(i, j int) bool {
			if edges[i].from.id != edges[j].from.id {
				return edges[i].from.id < edges[j].from.id
			}
			if edges[i].kind != edges[j].kind {
				return edges[i].kind < edges[j].kind
			}
			return edges[i].tag < edges[j].tag
		})
	}
}

// seedOrigins marks entry points as taint origins:
//   - calls to configured source functions,
//   - source-typed parameters with no in-package caller (entry handlers) or
//     that may be invoked externally,
//   - configured globals (e.g. os.Args).
func (e *Engine) seedOrigins(funcs []*ssa.Function) {
	originSeq := 0
	addOrigin := func(loc Loc, pos token.Pos, kind, label string) {
		o := Origin{id: originSeq, pos: pos, kind: kind, label: label}
		originSeq++
		e.origins[loc] = append(e.origins[loc], o)
		e.addTaint(loc.id, o.id)
	}

	for _, fn := range funcs {
		if fn == nil || fn.Blocks == nil {
			continue
		}
		// Source-typed parameters.
		for _, param := range fn.Params {
			if !e.rules.isTypeSource(param.Type()) {
				continue
			}
			if e.isEntryParameter(fn) {
				paramLoc := e.b.ls.locForValue(param)
				addOrigin(paramLoc, param.Pos(), "param-source",
					"entry param "+fn.Name()+"."+param.Name())
				// Every content region of a source-typed entry parameter is
				// attacker-controlled too, so field/element/map reads through
				// the parameter resolve to tainted locations at any depth.
				for _, region := range e.b.contentRegions(param) {
					addOrigin(region, param.Pos(), "param-source",
						"entry param "+fn.Name()+"."+param.Name())
				}
			}
		}
		// Source-typed globals are seeded from package members, not instructions.
		if fn.Pkg != nil {
			for _, member := range fn.Pkg.Members {
				if glob, ok := member.(*ssa.Global); ok {
					if glob.Pkg != nil && glob.Pkg.Pkg != nil {
						key := glob.Pkg.Pkg.Path() + "." + glob.Name()
						if _, ok := e.rules.globalSrcs[key]; ok {
							addOrigin(e.b.ls.locForValue(glob), glob.Pos(), "global-source", key)
						}
					}
				}
			}
		}
		// External configured globals (e.g. os.Args) are referenced through
		// instructions rather than declared in the analysis package. Seed both
		// the global location and, for a slice/array global, its elements.
		for _, glob := range e.b.globalRefs {
			if glob.Pkg == nil || glob.Pkg.Pkg == nil {
				continue
			}
			key := glob.Pkg.Pkg.Path() + "." + glob.Name()
			if _, ok := e.rules.globalSrcs[key]; !ok {
				continue
			}
			globLoc := e.b.ls.locForValue(glob)
			addOrigin(globLoc, glob.Pos(), "global-source", key)
			switch glob.Type().Underlying().(type) {
			case *types.Slice, *types.Array:
				addOrigin(e.b.ls.elemLoc(glob), glob.Pos(), "global-source", key+"[]")
			case *types.Map:
				addOrigin(e.b.ls.mapElemLoc(glob), glob.Pos(), "global-source", key+"[elem]")
			}
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				if v, ok := instr.(*ssa.Call); ok {
					if e.rules.isSourceFunc(v) {
						callee := v.Call.StaticCallee()
						addOrigin(e.b.ls.locForValue(v), v.Pos(), "func-source", funcIdentity(callee))
					}
				}
			}
		}
	}
}

// isEntryParameter reports whether a function parameter should be treated as an
// external taint entry: no in-graph callers (true entry point) or an exported
// bare function that frameworks may dispatch to invisibly.
func (e *Engine) isEntryParameter(fn *ssa.Function) bool {
	if fn.Signature == nil {
		return false
	}
	if e.cg == nil {
		return true
	}
	node := e.cg.Nodes[fn]
	if node == nil || len(node.In) == 0 {
		return true
	}
	if fn.Signature.Recv() == nil && fn.Parent() == nil && token.IsExported(fn.Name()) {
		return true
	}
	return false
}

// addTaint inserts an origin into a location set and reports whether the set
// grew.
func (e *Engine) addTaint(locID, originID int) bool {
	set, ok := e.tainted[locID]
	if !ok {
		set = make(map[int]struct{})
		e.tainted[locID] = set
	}
	if _, exists := set[originID]; exists {
		return false
	}
	set[originID] = struct{}{}
	return true
}

// solve drains the deterministic worklist. Locations are processed in ID order;
// each newly tainted location re-enqueues its outgoing successors.
func (e *Engine) solve() {
	// Initial worklist: every seeded location, sorted by ID.
	var worklist []int
	for locID := range e.tainted {
		worklist = append(worklist, locID)
	}
	sort.Ints(worklist)

	iterations := 0
	for len(worklist) > 0 {
		if iterations >= maxFixedPointIterations {
			e.cutoff = true
			e.notes = append(e.notes, "fixed-point iteration limit reached; remaining locations not evaluated")
			return
		}
		cur := worklist[0]
		worklist = worklist[1:]
		iterations++

		// Propagate along every edge whose source is cur. Origin sets are
		// iterated in sorted ID order so insertion into downstream sets is
		// schedule-independent.
		for _, ed := range e.outgoing(cur) {
			if ed.kind == edgeSanitizer {
				continue // sanitizer boundary: never propagate
			}
			// Constants are compile-time literals and can never carry
			// attacker-controlled data; never propagate taint into them.
			if loc := e.b.ls.all[ed.to.id]; loc.value != nil && isConstant(loc.value) {
				continue
			}
			grew := false
			for _, originID := range sortedOriginIDs(e.tainted[cur]) {
				if e.addTaint(ed.to.id, originID) {
					grew = true
				}
			}
			if grew {
				worklist = enqueueSorted(worklist, ed.to.id)
			}
		}
	}
}

func sortedOriginIDs(set map[int]struct{}) []int {
	out := make([]int, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

// outgoingCache memoizes forward adjacency built from the reverse index.
func (e *Engine) outgoing(locID int) []Edge {
	if e.outCache == nil {
		e.outCache = make(map[int][]Edge)
		for _, edges := range e.incoming {
			for _, ed := range edges {
				e.outCache[ed.from.id] = append(e.outCache[ed.from.id], ed)
			}
		}
		for from := range e.outCache {
			edges := e.outCache[from]
			sort.SliceStable(edges, func(i, j int) bool {
				if edges[i].to.id != edges[j].to.id {
					return edges[i].to.id < edges[j].to.id
				}
				return edges[i].tag < edges[j].tag
			})
		}
	}
	return e.outCache[locID]
}

// enqueueSorted inserts id keeping the worklist ascending, with no duplicates.
func enqueueSorted(worklist []int, id int) []int {
	idx := sort.SearchInts(worklist, id)
	if idx < len(worklist) && worklist[idx] == id {
		return worklist
	}
	worklist = append(worklist, 0)
	copy(worklist[idx+1:], worklist[idx:])
	worklist[idx] = id
	return worklist
}

// collectFindings evaluates every configured sink call against the fixed point.
func (e *Engine) collectFindings(funcs []*ssa.Function) []Finding {
	var findings []Finding
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
				spec, isSink := e.rules.matchSink(call)
				if !isSink {
					continue
				}
				if !e.guardsSatisfied(call, spec) {
					continue
				}
				finding := e.evaluateSink(fn, call, spec)
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
		}
	}
	sortFindings(findings)
	return findings
}

// evaluateSink checks the configured arguments and builds a trace when tainted.
func (e *Engine) evaluateSink(fn *ssa.Function, call *ssa.Call, spec sinkSpec) *Finding {
	var allOrigins []Origin
	var trace []TraceNode
	confidence := ConfidenceHigh
	var notes []string

	for _, arg := range spec.argsToCheck(call) {
		// A literal constant at the sink is untaintable regardless of any
		// edges elsewhere.
		if isConstant(arg) {
			continue
		}
		// A variadic argument reaches the sink packed inside a slice. Inspect
		// the slice's element region in addition to the slice value itself, so
		// exec.Command("sh", tainted) and similar variadic sinks are caught.
		locations := []Loc{e.b.ls.locForValue(arg)}
		if _, isSlice := arg.Type().Underlying().(*types.Slice); isSlice {
			locations = append(locations, e.b.ls.elemLoc(e.b.canonical(arg)))
		}
		for _, loc := range locations {
			originIDs, ok := e.tainted[loc.id]
			if !ok || len(originIDs) == 0 {
				continue
			}
			for id := range originIDs {
				if o := e.originByID(id); o != nil {
					allOrigins = append(allOrigins, *o)
				}
			}
			// Reconstruct one deterministic trace per argument.
			t, conf, argNotes := e.traceBack(loc)
			trace = append(trace, t...)
			if conf == ConfidenceMedium {
				confidence = ConfidenceMedium
			}
			notes = append(notes, argNotes...)
		}
	}
	if len(allOrigins) == 0 {
		return nil
	}
	sortOrigins(allOrigins)
	allOrigins = dedupOrigins(allOrigins)
	incomplete := false
	if e.cutoff {
		confidence = ConfidenceMedium
		incomplete = true
		notes = append(notes, "analysis incomplete: fixed-point limit reached before full evaluation")
	}
	if confidence == ConfidenceMedium {
		incomplete = true
	}
	return &Finding{
		SinkPos:    call.Pos(),
		SinkDetail: call.String(),
		Origins:    allOrigins,
		Trace:      trace,
		RunID:      e.runID,
		Incomplete: incomplete,
		Confidence: confidence,
		Notes:      dedupNotes(notes),
	}
}

// originByID resolves an origin identifier back to its Origin.
func (e *Engine) originByID(id int) *Origin {
	for _, os := range e.origins {
		for i := range os {
			if os[i].id == id {
				return &os[i]
			}
		}
	}
	return nil
}

// guardsSatisfied applies a sink's ArgTypeGuards, resolving interface
// conversions the same way the legacy matcher does.
func (e *Engine) guardsSatisfied(call *ssa.Call, spec sinkSpec) bool {
	if len(spec.spec.ArgTypeGuards) == 0 || e.prog == nil {
		return true
	}
	for argIdx, requiredPath := range spec.spec.ArgTypeGuards {
		if argIdx >= len(call.Call.Args) {
			return false
		}
		argType := resolveOriginalType(call.Call.Args[argIdx])
		required := lookupNamedType(requiredPath, e.prog)
		if required == nil {
			return false
		}
		if iface, ok := required.Underlying().(*types.Interface); ok {
			if !types.Implements(argType, iface) &&
				!types.Implements(types.NewPointer(argType), iface) {
				return false
			}
		} else if !types.Identical(argType, required) &&
			!types.Identical(argType, types.NewPointer(required)) {
			return false
		}
	}
	return true
}

// isContext mirrors the legacy exclusion of context.Context arguments.
func isContext(t types.Type) bool {
	for {
		ptr, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "context" && obj.Name() == "Context"
}
