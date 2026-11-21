# Cross-goroutine taint analysis (`taint/flow`)

This document states, precisely, what the forward whole-program taint engine
can and cannot reason about. Unknown items are surfaced in results rather than
silently treated as clean.

## Why a new engine

The legacy engine in `taint/` is a demand-driven, backward traversal scoped to
one function. It loses taint as soon as a value leaves the function: a send on
a channel, a goroutine spawn, a struct field handed to another function, a
closure capture, or a thread-safe container all terminate the chain. That is
the root cause behind "the direct call is reported but the channel/worker
version is not".

`taint/flow` replaces the traversal with a forward, inclusion-based fixed-point
computation over abstract locations. Taint is computed once for the whole
analysis unit and propagated along explicit data-flow edges, so a value that
crosses a goroutine boundary keeps its origin.

The legacy engine remains available as `taint.NewLegacyGosecAnalyzer` for
fallback and regression comparison. `taint.NewGosecAnalyzer` now runs the flow
engine.

## Forms that ARE tracked

### Channels and goroutines
- Unbuffered and buffered channels, send (`ch <- x`) and receive (`<-ch`),
  including `select` cases in both directions.
- `go f(...)` goroutine spawns and `defer f(...)`: arguments are bound to the
  spawned/deferred callee parameters exactly like a synchronous call.
- Fan-out (one producer, many workers) and fan-in (many producers, one
  consumer).
- Channel direction conversions (`chan T` to `chan<- T` / `<-chan T`) via
  `ssa.ChangeType`, unified through a union-find so all views share one region.

### Composite data
- Struct fields, including nested pointer fields and values returned from
  constructor/helper functions (`&T{Field: tainted}`, `x.Field`,
  `(*ptr).Field`).
- Slice and fixed-array element regions, `append`/`copy` backing-array sharing.
- Map keys and values, including map literals (`ssa.MapUpdate`) and lookups.
- Values boxed into / unboxed from interfaces (`MakeInterface`,
  `ChangeInterface`, `TypeAssert`).

### Calls and returns
- Static calls inside the analysis package: argument→parameter and
  return→result edges, including multi-return tuples.
- Interface invokes and function-value calls, resolved over every CHA
  implementation, with receiver taint propagated to the result.
- External/dependency and bodyless functions: modeled opaquely — every
  data-carrying argument (receiver included) conservatively reaches the result.
  This is what keeps stdlib helpers such as `(*http.Request).FormValue` and
  `fmt.Sprintf` sound.
- Variadic calls: packed-slice element regions are connected so positionally
  passed arguments stay reachable through the variadic parameter.
- Closures: free variables are bound at `MakeClosure`; reference captures are
  unioned with their bindings.

### Thread-safe containers
Modeled explicitly so values stored behind method calls do not vanish:
- `sync.Map`: `Store`, `Load`, `LoadOrStore`, `Swap`, `LoadAndDelete`.
- `atomic.Value`: `Store`, `Load`.
- `sync.Pool`: `Put`, `Get`.

### Sanitizers
A configured sanitizer suppresses propagation at its call boundary regardless
of where it sits in the chain — before a channel send or after a receive — so a
cleaned value reaching a sink is not reported.

## Determinism
Every map iteration is replaced by interned-location ID order or an explicit
sort. The worklist is drained in ascending ID order and findings are emitted in
a total order (sink position, then detail). Repeated runs over identical input
produce identical sets and ordering, independent of goroutine scheduling.

## Confidence, incompleteness and run binding
- A fully resolved flow is reported at **High** confidence.
- A flow whose channel boundary has no visible counterpart in the analysis unit
  is still reported, but at **Medium** confidence with a note naming the missing
  side. It is never dropped or called clean.
- If the fixed-point or trace-depth limit is reached, confirmed findings are
  retained, marked `Incomplete`, downgraded to Medium, and annotated. Each
  finding carries the `RunID` of the analysis run so partial results cannot be
  conflated with a different run.
- A package that fails to load or build SSA is recorded in the report's
  `Golang errors` section (see `Analyzer.recordPackageError`); it is not
  silently skipped.

## Forms that remain UNKNOWN / limited
These are honest limitations; where they can be detected at runtime they are
annotated rather than hidden.
- **Reflection-based data flow** (`reflect` field/index access) is not modeled;
  taint entering reflection is conservatively propagated at the call boundary
  but field paths inside reflection are not reconstructed.
- **`unsafe.Pointer` casts** can defeat type-based region reasoning; the engine
  keeps pointer locations but does not claim field precision across them.
- **Cross-package channels whose two endpoints are in separately analyzed
  packages** are only fully connected when both packages are part of the same
  SSA program; otherwise the medium-confidence counterpart rule applies.
- **`sync.Once.Do` callbacks** inherit closure free-variable taint but the
  once-region itself is not a dedicated store/load model (unlike sync.Map and
  atomic.Value).
- Path/field sensitivity is bounded: slices use one shared element region and
  maps one shared key and one shared value region (flow-insensitive by design,
  in exchange for linear performance).

## Performance
The engine is flow-insensitive and converges in monotonic inclusion steps.
Measured with `go test ./taint/flow -bench BenchmarkFlowEngine`:
- ~1.8 ms/op on a 180-function stress package with channel fan-out.
- ~6.3 ms/op at 500 functions — near-linear scaling.
There is no whole-program quadratic pass: CHA dispatch is pre-indexed by call
site, edges are deduplicated, and the worklist only re-enqueues locations whose
origin set grew.
