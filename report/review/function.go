package review

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
)

// functionIndex maps line ranges of a single file to the enclosing function.
// It is built lazily and reused while the caller streams findings for that
// file in order, so every source file is parsed at most once.
type functionIndex struct {
	path   string
	ranges []functionRange
	failed bool
}

type functionRange struct {
	start int
	end   int
	name  string
}

func loadFunctionIndex(path string) *functionIndex {
	idx := &functionIndex{path: path}
	src, err := os.ReadFile(path) // #nosec G304 -- path is a source file produced by the scan
	if err != nil {
		idx.failed = true
		return idx
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil || file == nil {
		idx.failed = true
		return idx
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		idx.ranges = append(idx.ranges, functionRange{
			start: fset.Position(fn.Body.Pos()).Line,
			end:   fset.Position(fn.Body.End()).Line,
			name:  functionName(fn),
		})
	}
	// Nested functions (function literals) are not named in the review report;
	// the innermost enclosing declaration is the useful unit for a reviewer.
	sort.Slice(idx.ranges, func(i, j int) bool { return idx.ranges[i].start < idx.ranges[j].start })
	return idx
}

func functionName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	switch t := recv.(type) {
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return fmt.Sprintf("(*%s).%s", ident.Name, fn.Name.Name)
		}
	case *ast.Ident:
		return fmt.Sprintf("%s.%s", t.Name, fn.Name.Name)
	}
	return fn.Name.Name
}

func (idx *functionIndex) nameAt(line int) string {
	if idx == nil || idx.failed || line <= 0 {
		return ""
	}
	for _, r := range idx.ranges {
		if line >= r.start && line <= r.end {
			return r.name
		}
	}
	return ""
}

// attachFunction fills in the Function field of findings streamed from the
// location-ordered spill. Because that spill is ordered by file, a single
// index is enough; the index is only rebuilt when the file changes.
func (b *Builder) attachFunction() func(Finding) (Finding, error) {
	var idx *functionIndex
	lastFile := "\x00"

	return func(f Finding) (Finding, error) {
		if f.Function != "" {
			return f, nil
		}
		if idx == nil || lastFile != f.File {
			idx = loadFunctionIndex(b.absolute(f.File))
			lastFile = f.File
		}
		f.Function = idx.nameAt(f.Line)
		return f, nil
	}
}

func (b *Builder) absolute(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	if len(b.opts.Roots) > 0 && b.opts.Roots[0] != "" {
		return filepath.Join(b.opts.Roots[0], filepath.FromSlash(rel))
	}
	return rel
}
