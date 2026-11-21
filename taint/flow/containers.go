package flow

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Modeled concurrency-safe containers. These types hide their stored values
// behind method calls (no direct SSA Store/Load), so without explicit modeling
// every value passing through them would silently end the taint chain — the
// "dedup table / counter table" blind spot called out in the requirements.
//
// Each entry maps a method identity to a transfer description:
//   - store methods move the data argument into a per-container region;
//   - load methods move that region into the call result.
var modeledMethods = map[string]containerModel{
	// sync.Map: Store/Load/LoadOrStore/Swap/Range.
	"(*sync.Map).Store":         {region: "map", storeArg: 1},
	"(*sync.Map).Load":          {region: "map", loadResult: 0},
	"(*sync.Map).LoadOrStore":   {region: "map", storeArg: 1, loadResult: 0},
	"(*sync.Map).Swap":          {region: "map", storeArg: 1, loadResult: 0},
	"(*sync.Map).LoadAndDelete": {region: "map", loadResult: 0},
	// atomic.Value: Store/Load.
	"(*atomic.Value).Store": {region: "val", storeArg: 1},
	"(*atomic.Value).Load":  {region: "val", loadResult: 0},
	// sync.Pool: Put/Get.
	"(*sync.Pool).Put": {region: "pool", storeArg: 1},
	"(*sync.Pool).Get": {region: "pool", loadResult: 0},
}

type containerModel struct {
	region     string
	storeArg   int // argument index (receiver is 0) stored into the region; -1 = none
	loadResult int // result tuple index loaded from the region; -1 = none
}

// scanModeledContainer emits edges for a modeled container call. It returns
// false when the call is not a modeled container method.
func (b *builder) scanModeledContainer(fn *ssa.Function, call *ssa.Call) bool {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return false
	}
	id := containerMethodID(callee)
	model, ok := modeledMethods[id]
	if !ok {
		// sync.Once.Do(fn) — the callback runs (potentially) once but may run on
		// another goroutine; model the callback's free variables as flowing into
		// the once region and back out is unnecessary: MakeClosure already binds
		// free variables, and the callback function itself is an argument we
		// treat as a normal flow target.
		return false
	}

	// The receiver (Args[0]) identifies the concrete container instance.
	if len(call.Call.Args) == 0 {
		return true
	}
	receiver := call.Call.Args[0]
	region := b.ls.specialLoc(containerRegionName(receiver, model.region), call.Pos())

	if model.storeArg >= 0 && model.storeArg < len(call.Call.Args) {
		b.addEdge(edgeSpecial, b.ls.locForValue(call.Call.Args[model.storeArg]), region, call, id)
	}
	if model.loadResult >= 0 {
		// Load-family calls return (value, ok/loaded); the value itself is the
		// call result tuple, unpacked via Extract. Connecting the region to the
		// call value covers both direct and Extract uses.
		b.addEdge(edgeSpecial, region, b.ls.locForValue(call), call, id)
	}
	return true
}

func containerMethodID(fn *ssa.Function) string {
	var b strings.Builder
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		b.WriteString("(*")
		if fn.Pkg != nil && fn.Pkg.Pkg != nil {
			b.WriteString(fn.Pkg.Pkg.Path())
		}
		b.WriteString(".")
		// Receiver type name without the package qualifier.
		b.WriteString(receiverTypeName(fn))
		b.WriteString(").")
	}
	b.WriteString(fn.Name())
	return b.String()
}

func receiverTypeName(fn *ssa.Function) string {
	recv := fn.Signature.Recv().Type()
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	if named, ok := recv.(*types.Named); ok {
		return named.Obj().Name()
	}
	return recv.String()
}

func containerRegionName(receiver ssa.Value, region string) string {
	return "container:" + receiver.Name() + "#" + region
}
