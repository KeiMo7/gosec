package flow

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// builder accumulates flow edges by scanning every instruction of every
// analyzed function. Interprocedural edges (call arguments/returns, goroutine
// entries, closures) are added separately once the whole set of functions is
// known, because callees and anonymous functions must already be registered.
type builder struct {
	ls       *locs
	rules    *RuleSet
	edges    []Edge
	concrete []Edge // value-to-value edges, already interned
	// deferred region edges are materialized after all union-find relations
	// are known, so composite regions resolve to canonical roots regardless
	// of scan order.
	deferred []deferredEdge
	// aliases map an address-producing value (FieldAddr/IndexAddr) to the
	// composite region it names, so a Store/Load through it resolves correctly.
	aliases map[ssa.Value]regionRef
	// uf canonicalizes pointer-like values (channels, allocs, maps) across
	// function and goroutine boundaries.
	uf *unionfind
	// analyzed is the set of functions belonging to the analysis unit. A call
	// to anything outside it (a stdlib or dependency function, even if SSA
	// built a body) is treated as opaque: data-carrying arguments flow to the
	// result, matching the legacy engine's conservative external handling.
	analyzed map[*ssa.Function]bool
	// unitPkgPath is the import path of the package under analysis. Calls into
	// any other package are modeled opaquely even when SSA provides bodies,
	// because those bodies belong to dependencies rather than the analysis unit.
	unitPkgPath string
	// globalRefs collects package-level variables referenced from instructions,
	// including globals in external packages, for source seeding.
	globalRefs []*ssa.Global
}

// setAnalyzed records the analysis-unit function set and package path.
func (b *builder) setAnalyzed(funcs []*ssa.Function) {
	b.analyzed = make(map[*ssa.Function]bool, len(funcs))
	for _, fn := range funcs {
		b.analyzed[fn] = true
		if b.unitPkgPath == "" && fn != nil && fn.Pkg != nil && fn.Pkg.Pkg != nil {
			b.unitPkgPath = fn.Pkg.Pkg.Path()
		}
	}
}

// inAnalysisUnit reports whether fn belongs to the package under analysis.
func (b *builder) inAnalysisUnit(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	return fn.Pkg.Pkg.Path() == b.unitPkgPath
}

// regionRef names a composite region relative to a base value, resolvable
// after union-find has settled.
type regionRef struct {
	kind  locKind
	base  ssa.Value
	field int
}

// deferredEdge keeps an edge whose endpoints may still need canonicalization.
type deferredEdge struct {
	kind edgeKind
	from edgeEndpoint
	to   edgeEndpoint
	site ssa.Instruction
	tag  string
}

// edgeEndpoint is either a plain value location or a region reference.
type edgeEndpoint struct {
	value  ssa.Value
	region *regionRef
}

func valueEndpoint(v ssa.Value) edgeEndpoint { return edgeEndpoint{value: v} }
func regionEndpoint(kind locKind, base ssa.Value, field int) edgeEndpoint {
	return edgeEndpoint{region: &regionRef{kind: kind, base: base, field: field}}
}

// addEdge records an interned value-to-value (or special-location) flow edge.
// Region-bearing edges go through addRegionEdge so union-find can settle first.
func (b *builder) addEdge(kind edgeKind, from, to Loc, site ssa.Instruction, tag string) {
	b.concrete = append(b.concrete, Edge{kind: kind, from: from, to: to, site: site, tag: tag})
}

func newBuilder(rules *RuleSet) *builder {
	return &builder{
		ls:      newLocs(),
		rules:   rules,
		aliases: make(map[ssa.Value]regionRef),
		uf:      newUnionFind(),
	}
}

// addRegionEdge records an edge whose endpoints are (possibly) composite
// regions. It is the deferred counterpart of addEdge.
func (b *builder) addRegionEdge(kind edgeKind, from, to edgeEndpoint, site ssa.Instruction, tag string) {
	b.deferred = append(b.deferred, deferredEdge{kind: kind, from: from, to: to, site: site, tag: tag})
}

// vLoc is shorthand for a value endpoint.
func vLoc(v ssa.Value) edgeEndpoint { return edgeEndpoint{value: v} }

// rLoc is shorthand for a region endpoint.
func rLoc(kind locKind, base ssa.Value, field int) edgeEndpoint {
	return edgeEndpoint{region: &regionRef{kind: kind, base: base, field: field}}
}

// materialize finalizes all deferred region edges once union-find is complete
// and merges them with the already-interned value edges.
func (b *builder) materialize() {
	b.edges = append(b.edges, b.concrete...)
	for _, d := range b.deferred {
		from := b.resolveEndpoint(d.from)
		to := b.resolveEndpoint(d.to)
		if from.value == nil && from.kind == 0 {
			continue
		}
		if to.value == nil && to.kind == 0 {
			continue
		}
		b.edges = append(b.edges, Edge{kind: d.kind, from: from, to: to, site: d.site, tag: d.tag})
	}
	b.materializeProjectionEdges()
	b.materializeReferenceFlows()
}

// materializeProjectionEdges adds value->content-region edges for every
// reference-typed value. Taint on a whole object therefore reaches its struct
// fields, slice/map elements and channel data, which is what makes nested
// accesses such as r.U.Query().Get(...) resolvable without per-field stores.
func (b *builder) materializeProjectionEdges() {
	seen := make(map[[2]int]bool)
	add := func(from, to Loc) {
		key := [2]int{from.id, to.id}
		if from.id == to.id || seen[key] {
			return
		}
		seen[key] = true
		b.edges = append(b.edges, Edge{kind: edgeCopy, from: from, to: to, tag: "project-content"})
	}
	// Iterate registered values in intern order for deterministic edge order.
	for _, l := range b.ls.sorted() {
		if l.value == nil || l.kind != locValue {
			continue
		}
		if !isReferenceType(l.value.Type()) {
			continue
		}
		root := b.canonical(l.value)
		for _, region := range b.contentRegions(root) {
			add(l, region)
		}
	}
}

// materializeReferenceFlows connects the content regions of reference-typed
// values (struct fields, slice/map elements) across channel hops. A channel
// region is kept distinct from the objects that pass through it, so these
// explicit edges carry field/element taint while the channel send/receive
// nodes remain visible in every reconstructed trace.
func (b *builder) materializeReferenceFlows() {
	var extra []Edge
	seen := make(map[[3]int]bool)
	add := func(kind edgeKind, from, to Loc, site ssa.Instruction, tag string) {
		key := [3]int{int(kind), from.id, to.id}
		if seen[key] {
			return
		}
		seen[key] = true
		extra = append(extra, Edge{kind: kind, from: from, to: to, site: site, tag: tag})
	}
	for _, d := range b.deferred {
		switch d.kind {
		case edgeChanSend:
			// Object content flows into the channel region.
			if d.from.value != nil && isReferenceType(d.from.value.Type()) {
				chanLoc := b.resolveEndpoint(d.to)
				for _, c := range b.contentRegions(d.from.value) {
					add(edgeChanSend, c, chanLoc, d.site, d.tag+"content-send")
				}
			}
		case edgeChanRecv:
			// Channel region flows into the received object's content.
			if d.to.value != nil && isReferenceType(d.to.value.Type()) {
				chanLoc := b.resolveEndpoint(d.from)
				for _, c := range b.contentRegions(d.to.value) {
					add(edgeChanRecv, chanLoc, c, d.site, d.tag+"content-recv")
				}
			}
		}
	}
	b.edges = append(b.edges, extra...)
}

// contentRegions returns the abstract content locations reachable inside a
// reference-typed value (struct fields, slice element, map key/element).
// Pointer-typed struct fields are followed one level so a tainted source
// parameter's nested objects are reachable.
func (b *builder) contentRegions(v ssa.Value) []Loc {
	return b.contentRegionsDepth(v, 0)
}

const maxContentDepth = 4

func (b *builder) contentRegionsDepth(v ssa.Value, depth int) []Loc {
	if depth > maxContentDepth {
		return nil
	}
	t := derefType(v.Type())
	var out []Loc
	switch ut := t.Underlying().(type) {
	case *types.Struct:
		root := b.canonical(v)
		for i := 0; i < ut.NumFields(); i++ {
			fieldLoc := b.ls.fieldLoc(root, i)
			out = append(out, fieldLoc)
			// Recurse into pointer/interface fields so nested struct content is
			// covered when the enclosing object is a taint source.
			ft := ut.Field(i).Type()
			if _, ok := ft.Underlying().(*types.Struct); ok {
				out = append(out, b.contentRegionsDepth(fieldValue{loc: fieldLoc, typ: ft}, depth+1)...)
			}
		}
	case *types.Slice, *types.Array:
		out = append(out, b.ls.elemLoc(b.canonical(v)))
	case *types.Map:
		out = append(out, b.ls.mapElemLoc(b.canonical(v)), b.ls.mapKeyLoc(b.canonical(v)))
	case *types.Chan:
		out = append(out, b.ls.chanLoc(b.canonical(v)))
	}
	return out
}

// fieldValue is a synthetic ssa.Value used only to recurse into nested struct
// fields when seeding content regions of a source-typed parameter.
type fieldValue struct {
	loc Loc
	typ types.Type
}

func (f fieldValue) Pos() token.Pos                { return f.loc.Pos() }
func (f fieldValue) Type() types.Type              { return f.typ }
func (f fieldValue) Name() string                  { return "nested-field" }
func (f fieldValue) Referrers() *[]ssa.Instruction { return nil }
func (f fieldValue) Parent() *ssa.Function         { return nil }
func (f fieldValue) Block() int                    { return 0 }
func (f fieldValue) String() string                { return f.typ.String() }

// derefType removes a leading pointer layer to inspect the referenced type.
func derefType(t types.Type) types.Type {
	if ptr, ok := t.(*types.Pointer); ok {
		return ptr.Elem()
	}
	return t
}

func (b *builder) resolveEndpoint(ep edgeEndpoint) Loc {
	if ep.region != nil {
		base := b.canonical(ep.region.base)
		switch ep.region.kind {
		case locField:
			return b.ls.fieldLoc(base, ep.region.field)
		case locIndex:
			return b.ls.elemLoc(base)
		case locMapKey:
			return b.ls.mapKeyLoc(base)
		case locMapElem:
			return b.ls.mapElemLoc(base)
		case locChan:
			return b.ls.chanLoc(base)
		}
	}
	if ep.value == nil {
		return Loc{}
	}
	return b.ls.locForValue(ep.value)
}

// canonical resolves a value to its union-find root so composite regions built
// in different functions on the same runtime object share one location.
func (b *builder) canonical(v ssa.Value) ssa.Value {
	if root := b.uf.find(v); root != nil {
		return root
	}
	return v
}

// cField/cElem/cMap/cChan return canonical composite regions.
func (b *builder) cField(base ssa.Value, field int) Loc {
	return b.ls.fieldLoc(b.canonical(base), field)
}

func (b *builder) cElem(base ssa.Value) Loc { return b.ls.elemLoc(b.canonical(base)) }
func (b *builder) cMapKey(base ssa.Value) Loc {
	return b.ls.mapKeyLoc(b.canonical(base))
}
func (b *builder) cMapElem(base ssa.Value) Loc {
	return b.ls.mapElemLoc(b.canonical(base))
}
func (b *builder) cChan(ch ssa.Value) Loc { return b.ls.chanLoc(b.canonical(ch)) }

// scanFunction walks one function body and emits intra-procedural edges.
func (b *builder) scanFunction(fn *ssa.Function) {
	if fn == nil || fn.Blocks == nil {
		return
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			b.scanInstr(fn, instr)
		}
	}
}

func (b *builder) scanInstr(fn *ssa.Function, instr ssa.Instruction) {
	switch v := instr.(type) {
	case *ssa.Call:
		b.scanCall(fn, v)

	case *ssa.Send:
		// ch <- x : the channel data region receives x directly. For a
		// reference value (map/slice/pointer-to-struct), the object's content
		// regions are linked to the channel region explicitly in
		// materializeReferenceFlows instead of merging identities, so the
		// channel hop stays a distinct, visible trace node.
		b.uf.add(v.Chan)
		b.addRegionEdge(edgeChanSend, vLoc(v.X), rLoc(locChan, v.Chan, 0), v, "")

	case *ssa.UnOp:
		// <-ch is *ssa.UnOp with token.ARROW; *p is token.MUL.
		if v.Op == token.ARROW {
			b.uf.add(v.X)
			b.addRegionEdge(edgeChanRecv, rLoc(locChan, v.X, 0), vLoc(v), v, "")
			return
		}
		if v.Op == token.MUL {
			// Dereferencing a package-level global (e.g. *os.Args): record the
			// global so external configured globals can be seeded as sources.
			if glob, ok := v.X.(*ssa.Global); ok {
				b.globalRefs = append(b.globalRefs, glob)
			}
			// A load through an aliased address (field/element) resolves to that
			// region; otherwise it is a plain pointer dereference.
			if alias, ok := b.aliases[v.X]; ok {
				b.addRegionEdge(edgeCopy, rLoc(alias.kind, alias.base, alias.field), vLoc(v), v, "load-alias")
				// Loading a reference-typed field yields the object the field
				// points at; its identity follows the field value, so unify the
				// loaded object with the field's base region. This keeps taint
				// flowing through nested pointer fields such as r.U.Query().
				if isReferenceType(v.Type()) {
					b.uf.union(v.X, v)
				}
			} else {
				// Pointer dereference: the loaded value *is* the object the
				// pointer names. Unify in both directions so a channel reached
				// through a *chan (escape via a local) keeps one region.
				if isReferenceType(v.Type()) {
					b.uf.union(v.X, v)
				}
				b.addEdge(edgeCopy, b.ls.locForValue(v.X), b.ls.locForValue(v), v, "deref")
			}
		}

	case *ssa.BinOp:
		b.addEdge(edgeCopy, b.ls.locForValue(v.X), b.ls.locForValue(v), v, "")
		b.addEdge(edgeCopy, b.ls.locForValue(v.Y), b.ls.locForValue(v), v, "")

	case *ssa.Phi:
		dst := b.ls.locForValue(v)
		for _, e := range v.Edges {
			b.addEdge(edgeCopy, b.ls.locForValue(e), dst, v, "")
		}

	case *ssa.Extract:
		b.addEdge(edgeCopy, b.ls.locForValue(v.Tuple), b.ls.locForValue(v), v, "")

	case *ssa.TypeAssert:
		b.addEdge(edgeCopy, b.ls.locForValue(v.X), b.ls.locForValue(v), v, "type-assert")

	case *ssa.MakeInterface:
		// Boxing a reference into an interface preserves the object identity:
		// unify so field/element taint on the concrete value reaches the
		// interface receiver and back out through invoked methods.
		if isReferenceType(v.X.Type()) {
			b.uf.union(v.X, v)
		}
		b.addEdge(edgeCopy, b.ls.locForValue(v.X), b.ls.locForValue(v), v, "make-interface")

	case *ssa.ChangeInterface:
		b.addEdge(edgeCopy, b.ls.locForValue(v.X), b.ls.locForValue(v), v, "change-interface")

	case *ssa.Convert:
		b.addEdge(edgeCopy, b.ls.locForValue(v.X), b.ls.locForValue(v), v, "convert")

	case *ssa.ChangeType:
		// chan<- / <-chan re-views of one channel, or other type-preserving
		// reference conversions, name the same object; unify so regions merge.
		if isReferenceType(v.X.Type()) {
			b.uf.union(v.X, v)
		}
		b.addEdge(edgeCopy, b.ls.locForValue(v.X), b.ls.locForValue(v), v, "change-type")

	case *ssa.Slice:
		// s = arr[:] : the resulting slice shares the backing array, so unify
		// the two and connect their element regions.
		b.uf.union(v.X, v)
		b.addRegionEdge(edgeCopy, rLoc(locIndex, v.X, 0), rLoc(locIndex, v, 0), v, "slice-backing")
		b.addEdge(edgeCopy, b.ls.locForValue(v.X), b.ls.locForValue(v), v, "")

	case *ssa.FieldAddr:
		// &x.Field names the field region for later loads/stores. Unify the
		// address with its base so container pointers passed as parameters
		// resolve to one canonical object everywhere.
		b.uf.union(v, v.X)
		b.aliases[v] = regionRef{kind: locField, base: v.X, field: v.Field}

	case *ssa.Field:
		// Value-form field access (non-addressable structs).
		b.addRegionEdge(edgeFieldLoad, rLoc(locField, v.X, v.Field), vLoc(v), v, "")

	case *ssa.IndexAddr:
		b.uf.union(v, v.X)
		b.aliases[v] = regionRef{kind: locIndex, base: v.X}

	case *ssa.Index:
		b.addRegionEdge(edgeIndexLoad, rLoc(locIndex, v.X, 0), vLoc(v), v, "")

	case *ssa.Lookup:
		if _, ok := v.X.Type().(*types.Map); ok {
			b.addRegionEdge(edgeMapLookup, rLoc(locMapElem, v.X, 0), vLoc(v), v, "")
		} else {
			b.addRegionEdge(edgeIndexLoad, rLoc(locIndex, v.X, 0), vLoc(v), v, "")
		}

	case *ssa.Store:
		b.scanStore(v)

	case *ssa.MakeClosure:
		// Free variables are bound at creation: closure freeVar <- binding.
		// When a reference (chan/map/slice/pointer) is captured, the free
		// variable names the same runtime object as the binding, so unify them.
		if closure, ok := v.Fn.(*ssa.Function); ok {
			for i, fv := range closure.FreeVars {
				if i < len(v.Bindings) {
					if isReferenceType(fv.Type()) {
						b.uf.union(v.Bindings[i], fv)
					}
					b.addEdge(edgeCopy, b.ls.locForValue(v.Bindings[i]), b.ls.locForValue(fv), v, "")
				}
			}
		}

	case *ssa.MakeMap, *ssa.MakeChan, *ssa.MakeSlice, *ssa.Alloc:
		// Declarations create locations but carry no flow by themselves.
		// Register them as union roots so later stores/derefs can unify.
		b.uf.add(instr.(ssa.Value))
		b.ls.locForValue(instr.(ssa.Value))

	case *ssa.MapUpdate:
		// m[k] = v : the value flows into the map's element region; the key
		// flows into its key region (relevant when keys are attacker controlled).
		if isReferenceType(v.Map.Type()) {
			b.uf.add(v.Map)
		}
		b.addRegionEdge(edgeMapStore, vLoc(v.Value), rLoc(locMapElem, v.Map, 0), v, "map-update")
		b.addRegionEdge(edgeMapStore, vLoc(v.Key), rLoc(locMapKey, v.Map, 0), v, "map-update-key")

	case *ssa.Select:
		b.scanSelect(v)
	}
}

// fieldAddrAliases / indexAddrAliases are handled through builder.aliases.

func (b *builder) scanStore(v *ssa.Store) {
	dst := v.Addr
	// An address produced by FieldAddr/IndexAddr is aliased to its region.
	if alias, ok := b.aliases[dst]; ok {
		// Map element store: m[k] = w targets the map's element region.
		if ia, isIndex := dst.(*ssa.IndexAddr); isIndex {
			if _, isMap := ia.X.Type().(*types.Map); isMap {
				b.addRegionEdge(edgeMapStore, vLoc(v.Val), rLoc(locMapElem, ia.X, 0), v, "map-store")
				return
			}
		}
		// A reference value stored through a pointer still names the same
		// runtime object, so unify it with the region's base (e.g. a channel
		// escaped into a *chan local).
		if isReferenceType(v.Val.Type()) {
			b.uf.union(v.Val, alias.base)
		}
		b.addRegionEdge(edgeCopy, vLoc(v.Val), rLoc(alias.kind, alias.base, alias.field), v, "store-alias")
		return
	}
	switch addr := dst.(type) {
	case *ssa.Global:
		if isReferenceType(v.Val.Type()) {
			b.uf.union(v.Val, addr)
		}
		b.addEdge(edgeCopy, b.ls.locForValue(v.Val), b.ls.locForValue(addr), v, "store-global")
	default:
		// Storing a reference (chan/map/slice/pointer) into a pointer local
		// makes the local an alias of the stored object.
		if isReferenceType(v.Val.Type()) {
			b.uf.union(v.Val, dst)
		}
		b.addEdge(edgeCopy, b.ls.locForValue(v.Val), b.ls.locForValue(dst), v, "store")
	}
}

// scanCall handles ordinary calls. Static calls with bodies get their
// interprocedural edges in buildInterprocedural; here we cover builtins,
// external functions, sanitizers and modeled concurrency containers.
func (b *builder) scanCall(fn *ssa.Function, call *ssa.Call) {
	// Interface/function-value dispatch without a static callee: the result
	// conservatively inherits taint from the receiver and every data-carrying
	// argument. Dynamic callees' return edges are also added globally via CHA,
	// but this keeps the flow sound even when no call graph is available.
	if call.Call.IsInvoke() || call.Call.StaticCallee() == nil {
		dst := b.ls.locForValue(call)
		if call.Call.Value != nil {
			b.addEdge(edgeCopy, b.ls.locForValue(call.Call.Value), dst, call, "invoke-receiver")
		}
		for _, arg := range call.Call.Args {
			if isContext(arg.Type()) {
				continue
			}
			// A variadic argument is packed into a slice at the call site;
			// propagate the element region so values passed positionally
			// (fmt.Sprintf("...", id)) reach the opaque/invoked result.
			if _, isSlice := arg.Type().Underlying().(*types.Slice); isSlice {
				b.addRegionEdge(edgeCopy, rLoc(locIndex, arg, 0), vLoc(call), call, "invoke-variadic-elem")
			}
			b.addEdge(edgeCopy, b.ls.locForValue(arg), dst, call, "invoke-arg")
		}
		return
	}

	// Sanitizer: record a suppressing edge on the call result so propagation
	// stops here even when arguments are tainted.
	if b.rules.isSanitizer(call) {
		b.addEdge(edgeSanitizer, b.ls.locForValue(call), b.ls.locForValue(call), call, "")
		return
	}

	// Modeled concurrency-safe containers (sync.Map, atomic.Value, once.Do ...).
	if b.scanModeledContainer(fn, call) {
		return
	}

	callee := call.Call.StaticCallee()
	// Only a callee with a real body inside the analysis package gets precise
	// interprocedural edges. A bodyless in-package declaration (external linker
	// function, assembly routine) and every dependency/stdlib call are modeled
	// opaquely so taint still flows through their results.
	if callee != nil && callee.Blocks != nil && b.inAnalysisUnit(callee) {
		return
	}

	if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
		b.scanBuiltin(call, builtin)
		return
	}

	// Opaque function: outside the analysis package or without a resolvable
	// body. Conservatively propagate every data-carrying argument, including
	// the receiver, to the result.
	dst := b.ls.locForValue(call)
	for _, arg := range call.Call.Args {
		if isContext(arg.Type()) {
			continue
		}
		// Propagate variadic-packed slice elements to the opaque result so
		// positional arguments such as fmt.Sprintf("...", tainted) are tracked.
		if _, isSlice := arg.Type().Underlying().(*types.Slice); isSlice {
			b.addRegionEdge(edgeCopy, rLoc(locIndex, arg, 0), vLoc(call), call, "external-variadic-elem")
		}
		b.addEdge(edgeCopy, b.ls.locForValue(arg), dst, call, "external:"+calleeName(call))
	}
}

func calleeName(call *ssa.Call) string {
	if c := call.Call.StaticCallee(); c != nil {
		return c.Name()
	}
	if call.Call.IsInvoke() {
		return call.Call.Method.Name()
	}
	return "dynamic"
}

func (b *builder) scanBuiltin(call *ssa.Call, builtin *ssa.Builtin) {
	dst := b.ls.locForValue(call)
	switch builtin.Name() {
	case "append":
		// append(s, elems...) : element region of the result merges s's region
		// and each appended value.
		if len(call.Call.Args) >= 1 {
			b.uf.union(call, call.Call.Args[0])
			b.addRegionEdge(edgeCopy, rLoc(locIndex, call.Call.Args[0], 0), rLoc(locIndex, call, 0), call, "append")
			for _, arg := range call.Call.Args[1:] {
				// A slice argument contributes its elements; a scalar contributes itself.
				if isContainer(arg.Type()) {
					b.addRegionEdge(edgeCopy, rLoc(locIndex, arg, 0), rLoc(locIndex, call, 0), call, "append-slice")
				} else {
					b.addRegionEdge(edgeCopy, vLoc(arg), rLoc(locIndex, call, 0), call, "append-elem")
				}
			}
			b.addEdge(edgeCopy, b.ls.locForValue(call.Call.Args[0]), dst, call, "append-base")
		}
	case "copy":
		if len(call.Call.Args) == 2 {
			b.addRegionEdge(edgeCopy, rLoc(locIndex, call.Call.Args[1], 0), rLoc(locIndex, call.Call.Args[0], 0), call, "copy")
		}
	case "delete", "close", "panic", "recover":
		// No data result to taint.
	case "len", "cap":
		// Numeric metadata, not data content.
	default:
		// String/[]byte conversions and similar: propagate operands.
		for _, arg := range call.Call.Args {
			b.addEdge(edgeCopy, b.ls.locForValue(arg), dst, call, "builtin:"+builtin.Name())
		}
	}
}

func (b *builder) scanSelect(v *ssa.Select) {
	// A select chooses one case statically-unknown at analysis time, so connect
	// every case's channel both directions: received values draw from the
	// channel region, sent values feed it.
	for _, state := range v.States {
		b.uf.add(state.Chan)
		if state.Dir == types.SendOnly {
			b.addRegionEdge(edgeChanSend, vLoc(state.Send), rLoc(locChan, state.Chan, 0), v, "select-send")
		} else {
			// RecvOnly: the tuple results (value, ok) are Extract-ed afterwards;
			// connect the select instruction itself to the channel region.
			b.addRegionEdge(edgeChanRecv, rLoc(locChan, state.Chan, 0), vLoc(v), v, "select-recv")
		}
	}
}
