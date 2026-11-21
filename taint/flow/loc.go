// Package flow implements a whole-program, flow-insensitive, inclusion-based
// taint analysis that tracks tainted data across function, goroutine and
// channel boundaries.
//
// The engine is a forward, worklist-driven fixed-point computation over
// abstract locations (see loc.go). Unlike a demand-driven backward traversal,
// it computes the taint state of every location once, so a value sent through
// a channel in one goroutine and received in another keeps its origin because
// both operations name the same abstract channel location.
//
// Determinism is a hard requirement: every iteration order over a map is
// replaced by ID order or an explicit sort, so the set and ordering of
// findings never depend on goroutine scheduling or Go's randomized maps.
package flow

import (
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/ssa"
)

// locKind enumerates the abstract location kinds.
type locKind int

const (
	locValue   locKind = iota // an SSA value (register, parameter, global, free var)
	locField                  // a struct field, qualified by its containing alloc/global
	locIndex                  // a slice/array element region (all indices share one region)
	locMapKey                 // the key region of a map
	locMapElem                // the value region of a map
	locChan                   // the data region of a channel
	locSpecial                // a modeled container (sync.Map, atomic.Value, once.Do ...)
)

// Loc is an abstract location identifier. Locations are interned: equal
// abstract locations share one ID, which keeps sets small and makes every
// iteration order deterministic.
type Loc struct {
	id    int
	kind  locKind
	value ssa.Value // for locValue: the value itself; for composite regions: the base
	field int       // locField: struct field index
	name  string    // locSpecial: modeled member name, e.g. "atomic.Value.Load"
	pos   token.Pos // stable tie-breaker for diagnostics
}

// ID returns the interned numeric identifier.
func (l Loc) ID() int { return l.id }

// Pos returns a source position associated with the location, if any.
func (l Loc) Pos() token.Pos {
	if l.value != nil {
		return l.value.Pos()
	}
	return l.pos
}

func (l Loc) String() string {
	if l.value == nil {
		return l.name
	}
	switch l.kind {
	case locField:
		return typeName(l.value) + ".field#" + strconv.Itoa(l.field)
	case locIndex:
		return typeName(l.value) + "[]elem"
	case locMapKey:
		return typeName(l.value) + "[key]"
	case locMapElem:
		return typeName(l.value) + "[elem]"
	case locChan:
		return typeName(l.value) + "<-chan"
	case locSpecial:
		return l.name
	default:
		return valueName(l.value)
	}
}

func typeName(v ssa.Value) string {
	if v == nil || v.Type() == nil {
		return "?"
	}
	return v.Type().String()
}

func valueName(v ssa.Value) string {
	switch val := v.(type) {
	case *ssa.Parameter:
		return "param:" + val.Name()
	case *ssa.Global:
		return "global:" + val.Name()
	case *ssa.FreeVar:
		return "freevar:" + val.Name()
	case *ssa.Function:
		return "func:" + val.String()
	default:
		return v.Name() + "(" + v.Type().String() + ")"
	}
}

// locs interns abstract locations.
type locs struct {
	values  map[ssa.Value]Loc
	comps   map[compKey]Loc
	special map[string]Loc
	all     []Loc
}

type compKey struct {
	kind  locKind
	base  ssa.Value
	field int
	name  string
}

func newLocs() *locs {
	return &locs{
		values:  make(map[ssa.Value]Loc),
		comps:   make(map[compKey]Loc),
		special: make(map[string]Loc),
	}
}

func (ls *locs) register(v ssa.Value) Loc {
	if v == nil {
		return Loc{}
	}
	if l, ok := ls.values[v]; ok {
		return l
	}
	l := Loc{id: len(ls.all), kind: locValue, value: v, pos: v.Pos()}
	ls.values[v] = l
	ls.all = append(ls.all, l)
	return l
}

func (ls *locs) composite(kind locKind, base ssa.Value, field int, name string) Loc {
	key := compKey{kind: kind, base: base, field: field, name: name}
	if l, ok := ls.comps[key]; ok {
		return l
	}
	l := Loc{id: len(ls.all), kind: kind, value: base, field: field, name: name, pos: base.Pos()}
	ls.comps[key] = l
	ls.all = append(ls.all, l)
	return l
}

func (ls *locs) specialLoc(name string, pos token.Pos) Loc {
	if l, ok := ls.special[name]; ok {
		return l
	}
	l := Loc{id: len(ls.all), kind: locSpecial, name: name, pos: pos}
	ls.special[name] = l
	ls.all = append(ls.all, l)
	return l
}

// sorted returns all locations in ID order.
func (ls *locs) sorted() []Loc {
	return ls.all
}

// locForValue returns the registered location of a value, registering it on
// demand. Constants are excluded by callers because they can never be tainted.
func (ls *locs) locForValue(v ssa.Value) Loc {
	if v == nil {
		return Loc{}
	}
	return ls.register(v)
}

// fieldLoc returns the location of a struct field reached through base.
func (ls *locs) fieldLoc(base ssa.Value, field int) Loc {
	return ls.composite(locField, base, field, "")
}

// elemLoc returns the shared element region of a slice/array.
func (ls *locs) elemLoc(base ssa.Value) Loc {
	return ls.composite(locIndex, base, 0, "")
}

// mapKeyLoc / mapElemLoc return the key and value regions of a map.
func (ls *locs) mapKeyLoc(base ssa.Value) Loc  { return ls.composite(locMapKey, base, 0, "") }
func (ls *locs) mapElemLoc(base ssa.Value) Loc { return ls.composite(locMapElem, base, 0, "") }

// chanLoc returns the data region of a channel.
func (ls *locs) chanLoc(ch ssa.Value) Loc { return ls.composite(locChan, ch, 0, "") }

// isContainer reports whether a type is a channel, map, slice or array and
// therefore carries element regions.
func isContainer(t types.Type) bool {
	switch t.(type) {
	case *types.Chan, *types.Map, *types.Slice, *types.Array:
		return true
	}
	return false
}
