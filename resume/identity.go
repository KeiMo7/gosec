package resume

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Plan describes the stable identity and current content fingerprint of one
// package directory before it is loaded for analysis.
type Plan struct {
	// Path is the package directory as supplied on the command line (kept
	// only for driving the loader; it is never persisted as an identity).
	Path string
	// Key is the stable identity key (see packageKey).
	Key string
	// Identity is the human-readable stable identity. It combines the module
	// path and the directory relative to the module root, so it is identical
	// on every machine that checks out the same repository.
	Identity string
	// Fingerprint is the content hash of every Go file that participates in
	// the build (with the requested build tags) plus the go.mod/go.sum files
	// that govern the package. Any content change changes the fingerprint.
	Fingerprint string
	// ModuleRoot is the directory containing the governing go.mod, or "" for
	// packages outside a module.
	ModuleRoot string
	// NoGo is true when the directory contains no buildable Go files for the
	// configured tags. Such packages are skipped by the loader today and are
	// recorded so repeated runs keep skipping them without rescanning.
	NoGo bool
}

// Planner computes package Plans. It is safe for concurrent use because the
// underlying build.Context and hash inputs are read-only.
type Planner struct {
	buildCtx build.Context
	gopaths  []string
	tests    bool
}

// NewPlanner builds a Planner for the given build tags. When tests is false
// (the gosec default), test files are excluded from fingerprints so changing
// them does not invalidate the state of a scan that never looks at them.
func NewPlanner(buildTags []string, tests bool) *Planner {
	ctx := build.Default
	ctx.BuildTags = append([]string(nil), buildTags...)
	return &Planner{
		buildCtx: ctx,
		gopaths:  gopaths(),
		tests:    tests,
	}
}

// gopaths returns absolute GOPATH roots, defaulting to build.Default.GOPATH.
func gopaths() []string {
	raw := build.Default.GOPATH
	if raw == "" {
		return nil
	}
	parts := filepath.SplitList(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if abs, err := filepath.Abs(p); err == nil {
			out = append(out, abs)
		}
	}
	return out
}

// findModuleRoot walks upward from dir until a go.mod file is found.
func findModuleRoot(dir string) string {
	dir = filepath.Clean(dir)
	for {
		if fi, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// modulePath reads the module path declared in the go.mod of root without
// pulling in a full module graph.
func modulePath(root string) (string, error) {
	f, err := os.Open(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	defer f.Close() // #nosec G307
	// A hand-rolled minimal parser avoids depending on golang.org/x/mod, and
	// only the leading "module <path>" directive is needed.
	var module string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "module") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "module"))
			rest = strings.Trim(rest, "\"`")
			module = strings.Fields(rest)[0]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if module == "" {
		return "", errors.New("go.mod has no module directive")
	}
	return module, nil
}

// relativeIdentity builds an identity that is stable across checkouts by
// combining a scope (module path or GOPATH marker) with the directory relative
// to that scope.
func relativeIdentity(scope, root, absDir string) string {
	rel, err := filepath.Rel(root, absDir)
	if err != nil {
		rel = filepath.Base(absDir)
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		rel = ""
	}
	if rel == "" {
		return scope
	}
	return scope + ":" + rel
}

// PlanPackage computes the Plan for one package directory.
func (p *Planner) PlanPackage(pkgPath string) (*Plan, error) {
	abs, err := filepath.Abs(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("resolving package path %q: %w", pkgPath, err)
	}
	if fi, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("package path %q: %w", pkgPath, err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("package path %q is not a directory", pkgPath)
	}

	identity, moduleRoot := p.identity(abs)

	bp, err := p.buildCtx.ImportDir(abs, build.ImportComment)
	noGo := false
	if err != nil {
		var noGoErr *build.NoGoError
		if !errors.As(err, &noGoErr) {
			return nil, fmt.Errorf("importing dir %q: %w", abs, err)
		}
		noGo = true
	}

	files := make([]string, 0)
	if bp != nil {
		for _, name := range bp.GoFiles {
			files = append(files, filepath.Join(abs, name))
		}
		for _, name := range bp.CgoFiles {
			files = append(files, filepath.Join(abs, name))
		}
		if p.tests {
			for _, name := range bp.TestGoFiles {
				files = append(files, filepath.Join(abs, name))
			}
			for _, name := range bp.XTestGoFiles {
				files = append(files, filepath.Join(abs, name))
			}
		}
	}

	fingerprint, err := contentFingerprint(abs, moduleRoot, files)
	if err != nil {
		return nil, err
	}

	key := packageKey(identity)
	return &Plan{
		Path:        pkgPath,
		Key:         key,
		Identity:    identity,
		Fingerprint: fingerprint,
		ModuleRoot:  moduleRoot,
		NoGo:        noGo,
	}, nil
}

// identity determines the stable, absolute-path-free identity of the package
// at abs. Module mode is preferred; GOPATH and ad-hoc directories fall back
// to scope markers. The ad-hoc fallback still hashes the absolute location so
// two same-named directories in different places do not collide, while the
// identity string itself never embeds the absolute path.
func (p *Planner) identity(abs string) (string, string) {
	if root := findModuleRoot(abs); root != "" {
		mod, err := modulePath(root)
		if err == nil {
			return relativeIdentity(mod, root, abs), root
		}
	}
	for _, gp := range p.gopaths {
		src := filepath.Join(gp, "src")
		if rel, err := filepath.Rel(src, abs); err == nil && !strings.HasPrefix(rel, "..") {
			return relativeIdentity("gopath", src, abs), ""
		}
	}
	// Sources outside any module/GOPATH: disambiguate same-named directories
	// with a location hash, keeping the human-readable base name for logs.
	return "adhoc:" + filepath.ToSlash(filepath.Base(abs)) + "#" + packageKey(abs), ""
}

// contentFingerprint hashes the relative path and contents of every selected
// Go file, together with the go.mod/go.sum governing the build. Entries are
// sorted so the hash is independent of filesystem iteration order.
func contentFingerprint(abs, moduleRoot string, goFiles []string) (string, error) {
	type entry struct {
		rel  string
		path string
	}
	entries := make([]entry, 0, len(goFiles)+2)
	seen := map[string]bool{}
	add := func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		rel, err := filepath.Rel(abs, path)
		if err != nil {
			rel = filepath.Base(path)
		}
		entries = append(entries, entry{rel: filepath.ToSlash(rel), path: path})
	}
	for _, f := range goFiles {
		add(f)
	}
	if moduleRoot != "" {
		add(filepath.Join(moduleRoot, "go.mod"))
		if fi, err := os.Stat(filepath.Join(moduleRoot, "go.sum")); err == nil && !fi.IsDir() {
			add(filepath.Join(moduleRoot, "go.sum"))
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	h := sha256.New()
	for _, e := range entries {
		data, err := os.ReadFile(e.path)
		if err != nil {
			return "", fmt.Errorf("fingerprinting %q: %w", e.path, err)
		}
		fmt.Fprintf(h, "%s\x00%d\x00", e.rel, len(data))
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
