package flow

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// Origin identifies one taint source occurrence. Findings and traces always
// reference an origin, so a result can never be reported without a concrete
// entry point even after many propagation steps.
type Origin struct {
	id    int
	pos   token.Pos
	kind  string // "func-source", "param-source", "global-source"
	label string // human-readable identity, e.g. "os.Getenv"
}

// Pos returns the source position of the origin.
func (o Origin) Pos() token.Pos { return o.pos }

// Label returns the human-readable origin identity.
func (o Origin) Label() string { return o.label }

// edgeKind enumerates data-flow edge kinds.
type edgeKind int

const (
	edgeCopy       edgeKind = iota // dst location receives everything src holds
	edgeFieldLoad                  // dst <- src.field
	edgeFieldStore                 // dst.field <- src
	edgeIndexLoad                  // dst <- src[]elem (slice/array load)
	edgeIndexStore                 // src[]elem <- dst value
	edgeMapLookup                  // dst <- map[elem]
	edgeMapStore                   // map[key], map[elem] <- values
	edgeChanSend                   // chan region <- sent value
	edgeChanRecv                   // dst <- chan region
	edgeSpecial                    // modeled container transfer, described by tag
	edgeCallArg                    // callee param <- caller argument
	edgeCallReturn                 // caller result <- callee return value
	edgeSanitizer                  // src is sanitized: propagation is suppressed
)

// Edge is one directed data-flow relation between abstract locations.
type Edge struct {
	kind edgeKind
	from Loc
	to   Loc
	// site is the instruction that induced the edge, used to build traces.
	site ssa.Instruction
	tag  string // edgeSpecial: model tag (e.g. "atomic.Store")
}

// TraceNode is one hop in a reconstructed propagation path.
type TraceNode struct {
	Pos    token.Pos
	Kind   string
	Detail string
	Func   *ssa.Function
}

// Finding is a confirmed source-to-sink flow.
type Finding struct {
	RuleID     string
	SinkPos    token.Pos
	SinkDetail string
	Origins    []Origin
	Trace      []TraceNode
	// RunID binds the finding to the analysis run that produced it, so partial
	// results kept after an interruption can never be confused with findings
	// from a different run.
	RunID string
	// Incomplete marks a finding produced under a degraded condition
	// (fixed-point cutoff, unresolved trace depth, or a missing counterpart).
	Incomplete bool
	// Confidence is High for fully-resolved flows, Medium when one side of a
	// concurrency boundary lies outside the analysis unit.
	Confidence confidence
	// Notes carries non-fatal caveats (missing counterpart, depth cut, ...).
	Notes []string
}

type confidence int

const (
	ConfidenceHigh confidence = iota
	ConfidenceMedium
)
