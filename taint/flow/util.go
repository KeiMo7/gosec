package flow

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// resolveOriginalType traces interface-conversion instructions back to the
// concrete value type, mirroring the legacy engine's guard resolution.
func resolveOriginalType(v ssa.Value) types.Type {
	switch val := v.(type) {
	case *ssa.ChangeInterface:
		return resolveOriginalType(val.X)
	case *ssa.MakeInterface:
		return val.X.Type()
	}
	return v.Type()
}

// lookupNamedType resolves "import/path.TypeName" against the SSA program.
func lookupNamedType(typePath string, prog *ssa.Program) types.Type {
	lastDot := strings.LastIndex(typePath, ".")
	if lastDot < 0 {
		return nil
	}
	pkgPath := typePath[:lastDot]
	typeName := typePath[lastDot+1:]
	for _, pkg := range prog.AllPackages() {
		if pkg.Pkg == nil || pkg.Pkg.Path() != pkgPath {
			continue
		}
		member := pkg.Pkg.Scope().Lookup(typeName)
		if member == nil {
			continue
		}
		if tn, ok := member.(*types.TypeName); ok {
			return tn.Type()
		}
	}
	return nil
}

// AllFunctions is the exported wrapper around allFunctions for integration
// tests and diagnostics in other packages.
func AllFunctions(prog *ssa.Program, pkg *ssa.Package) []*ssa.Function {
	return allFunctions(prog, pkg)
}

// allFunctions expands an SSA package's members into the complete analyzable
// function set, including named-type methods and anonymous closures nested at
// any depth.
func allFunctions(prog *ssa.Program, pkg *ssa.Package) []*ssa.Function {
	var out []*ssa.Function
	seen := make(map[*ssa.Function]bool)
	var walk func(fn *ssa.Function)
	walk = func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		var queue []*ssa.Function
		queue = append(queue, fn)
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			out = append(out, cur)
			queue = append(queue, cur.AnonFuncs...)
		}
	}
	// Top-level functions and variables; type members carry the method sets.
	for _, member := range pkg.Members {
		switch m := member.(type) {
		case *ssa.Function:
			walk(m)
		case *ssa.Type:
			named, ok := m.Type().(*types.Named)
			if !ok {
				continue
			}
			for i := 0; i < named.NumMethods(); i++ {
				meth := named.Method(i)
				// LookupMethod panics when the receiver form has no such
				// method (e.g. a pointer-only method on the value type).
				if fn := safeLookupMethod(prog, named, pkg.Pkg, meth.Name()); fn != nil {
					walk(fn)
				}
				if fn := safeLookupMethod(prog, types.NewPointer(named), pkg.Pkg, meth.Name()); fn != nil {
					walk(fn)
				}
			}
		}
	}
	return out
}

// safeLookupMethod calls LookupMethod and recovers its panic for receiver
// forms that do not declare the named method.
func safeLookupMethod(prog *ssa.Program, t types.Type, pkg *types.Package, name string) (fn *ssa.Function) {
	defer func() { _ = recover() }()
	return prog.LookupMethod(t, pkg, name)
}

// isConstant reports whether v is a compile-time constant literal.
func isConstant(v ssa.Value) bool {
	_, ok := v.(*ssa.Const)
	return ok
}

// isReferenceType reports whether a value names a shared runtime object whose
// identity is preserved across a call (the caller's argument and the callee's
// parameter refer to the same channel/map/slice/pointer/interface).
func isReferenceType(t types.Type) bool {
	if named, ok := t.(*types.Named); ok {
		t = named.Underlying()
	}
	switch t.(type) {
	case *types.Pointer, *types.Chan, *types.Map, *types.Slice, *types.Interface:
		return true
	}
	return false
}
