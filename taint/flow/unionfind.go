package flow

import (
	"golang.org/x/tools/go/ssa"
)

// unionfind canonicalizes pointer-like SSA values. A channel created in one
// function and sent/received in another is represented by different SSA
// values connected through parameters, loads and field accesses; without
// unifying them, the channel region at the send site would not be the same
// location as the region at the receive site and every cross-goroutine flow
// would silently stop. The same applies to allocs reached through parameters
// and container receivers.
type unionfind struct {
	parent map[ssa.Value]ssa.Value
}

func newUnionFind() *unionfind {
	return &unionfind{parent: make(map[ssa.Value]ssa.Value)}
}

func (u *unionfind) add(v ssa.Value) {
	if v == nil {
		return
	}
	if _, ok := u.parent[v]; !ok {
		u.parent[v] = v
	}
}

// union declares a and b the same abstract object.
func (u *unionfind) union(a, b ssa.Value) {
	if a == nil || b == nil {
		return
	}
	u.add(a)
	u.add(b)
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		// Tie-break deterministically by value identity order.
		if valueLess(ra, rb) {
			u.parent[rb] = ra
		} else {
			u.parent[ra] = rb
		}
	}
}

func (u *unionfind) find(v ssa.Value) ssa.Value {
	if v == nil {
		return nil
	}
	root := v
	for u.parent[root] != nil && u.parent[root] != root {
		root = u.parent[root]
	}
	// Path compression.
	for cur := v; u.parent[cur] != nil && u.parent[cur] != cur; {
		next := u.parent[cur]
		u.parent[cur] = root
		cur = next
	}
	return root
}

// valueLess gives union roots a deterministic order, preferring creation
// instructions over derived values so the canonical name is the origin.
func valueLess(a, b ssa.Value) bool {
	// Alloc/MakeChan/MakeMap/MakeSlice are "creation" values and win roots.
	aCreate := isCreationValue(a)
	bCreate := isCreationValue(b)
	if aCreate != bCreate {
		return aCreate
	}
	if a.Pos() != b.Pos() {
		return a.Pos() < b.Pos()
	}
	return valueName(a) < valueName(b)
}

func isCreationValue(v ssa.Value) bool {
	switch v.(type) {
	case *ssa.Alloc, *ssa.MakeChan, *ssa.MakeMap, *ssa.MakeSlice, *ssa.Global:
		return true
	}
	return false
}
