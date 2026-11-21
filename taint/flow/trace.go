package flow

import (
	"go/token"
	"sort"

	"golang.org/x/tools/go/ssa"
)

// maxTraceDepth bounds backward path reconstruction. When reached, the partial
// trace is kept and an "unresolved" note is attached — the flow is never
// mislabeled as sanitized.
const maxTraceDepth = 60

// traceBack reconstructs a deterministic propagation path from a tainted sink
// argument back to its origins by walking reverse edges in ID order.
func (e *Engine) traceBack(sinkLoc Loc) ([]TraceNode, confidence, []string) {
	type frame struct {
		loc   Loc
		depth int
	}
	var (
		trace      []TraceNode
		visited    = map[int]bool{sinkLoc.id: true}
		stack      = []frame{{sinkLoc, 0}}
		confidence = ConfidenceHigh
		notes      []string
	)

	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur.depth >= maxTraceDepth {
			notes = append(notes, "trace depth limit reached; path beyond this point unresolved")
			confidence = ConfidenceMedium
			continue
		}

		// Record a node for every tainted incoming edge. Edges are already
		// sorted by source ID, so the walk is deterministic.
		inEdges := e.incoming[cur.loc.id]
		for _, ed := range inEdges {
			if _, tainted := e.tainted[ed.from.id]; !tainted {
				continue
			}
			node := TraceNode{
				Pos:    edgePos(ed),
				Kind:   edgeKindName(ed.kind),
				Detail: ed.tag,
			}
			if ed.site != nil {
				node.Func = enclosingFunc(ed.site)
			}
			trace = append(trace, node)

			// Channel edges whose counterpart is absent from the analyzed set
			// can only be reported at medium confidence.
			if ed.kind == edgeChanSend || ed.kind == edgeChanRecv {
				if !e.counterpartPresent(ed) {
					confidence = ConfidenceMedium
					notes = append(notes, "channel boundary crosses the analysis unit; counterpart not visible: "+e.b.ls.all[ed.from.id].String())
				}
			}

			if !visited[ed.from.id] {
				visited[ed.from.id] = true
				stack = append(stack, frame{ed.from, cur.depth + 1})
			}
		}
	}

	// Origins close the trace: append one node per distinct origin position.
	for loc, os := range e.origins {
		if _, tainted := e.tainted[sinkLoc.id]; !tainted {
			continue
		}
		for _, o := range os {
			if e.originReaches(o.id, sinkLoc.id) {
				_ = loc
				trace = append(trace, TraceNode{Pos: o.pos, Kind: o.kind, Detail: o.label})
			}
		}
	}
	sortTrace(trace)
	return dedupTrace(trace), confidence, dedupNotes(notes)
}

// originReaches is a short reachability check used only to label trace ends;
// the authoritative taint set is computed by solve().
func (e *Engine) originReaches(originID, sinkID int) bool {
	set, ok := e.tainted[sinkID]
	if !ok {
		return false
	}
	_, ok = set[originID]
	return ok
}

// counterpartPresent reports whether a channel edge's channel region has both
// a send and a receive edge within the analyzed set.
func (e *Engine) counterpartPresent(ed Edge) bool {
	region := ed.to
	if ed.kind == edgeChanRecv {
		region = ed.from
	}
	hasSend, hasRecv := false, false
	for _, in := range e.incoming[region.id] {
		if in.kind == edgeChanSend {
			hasSend = true
		}
	}
	for _, out := range e.outgoing(region.id) {
		if out.kind == edgeChanRecv {
			hasRecv = true
		}
	}
	return hasSend && hasRecv
}

func edgePos(ed Edge) token.Pos {
	if ed.site != nil {
		return ed.site.Pos()
	}
	return token.NoPos
}

func enclosingFunc(instr ssa.Instruction) *ssa.Function {
	if fn := instr.Parent(); fn != nil {
		return fn
	}
	return nil
}

func edgeKindName(k edgeKind) string {
	switch k {
	case edgeCopy:
		return "copy"
	case edgeFieldLoad:
		return "field-load"
	case edgeFieldStore:
		return "field-store"
	case edgeIndexLoad:
		return "index-load"
	case edgeIndexStore:
		return "index-store"
	case edgeMapLookup:
		return "map-lookup"
	case edgeMapStore:
		return "map-store"
	case edgeChanSend:
		return "chan-send"
	case edgeChanRecv:
		return "chan-recv"
	case edgeSpecial:
		return "container"
	case edgeCallArg:
		return "call-arg"
	case edgeCallReturn:
		return "call-return"
	case edgeSanitizer:
		return "sanitizer"
	default:
		return "flow"
	}
}

func sortTrace(t []TraceNode) {
	sort.SliceStable(t, func(i, j int) bool {
		if t[i].Pos != t[j].Pos {
			return t[i].Pos < t[j].Pos
		}
		if t[i].Kind != t[j].Kind {
			return t[i].Kind < t[j].Kind
		}
		return t[i].Detail < t[j].Detail
	})
}

func dedupTrace(t []TraceNode) []TraceNode {
	if len(t) <= 1 {
		return t
	}
	out := t[:1]
	for i := 1; i < len(t); i++ {
		prev := t[i-1]
		cur := t[i]
		if prev.Pos == cur.Pos && prev.Kind == cur.Kind && prev.Detail == cur.Detail {
			continue
		}
		out = append(out, cur)
	}
	return out
}

func sortOrigins(o []Origin) {
	sort.SliceStable(o, func(i, j int) bool {
		if o[i].pos != o[j].pos {
			return o[i].pos < o[j].pos
		}
		return o[i].label < o[j].label
	})
}

func dedupOrigins(o []Origin) []Origin {
	seen := make(map[int]bool, len(o))
	out := make([]Origin, 0, len(o))
	for _, x := range o {
		if seen[x.id] {
			continue
		}
		seen[x.id] = true
		out = append(out, x)
	}
	return out
}

func dedupNotes(notes []string) []string {
	seen := make(map[string]bool, len(notes))
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// sortFindings gives a run-independent total order: sink position, then detail.
func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].SinkPos != f[j].SinkPos {
			return f[i].SinkPos < f[j].SinkPos
		}
		return f[i].SinkDetail < f[j].SinkDetail
	})
}
