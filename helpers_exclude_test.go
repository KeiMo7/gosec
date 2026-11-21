package gosec_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/securego/gosec/v2"
)

// FindPackagePaths has to report exactly which directories were excluded, so a
// review report can say what was not scanned.
func TestFindPackagePathsReportsExcludedDirs(t *testing.T) {
	root := t.TempDir()
	mkdir := func(rel string) {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(rel)), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	writeGo := func(rel string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte("package p\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	mkdir("app")
	writeGo("app/a.go")
	writeGo("vendor/lib/v.go")
	writeGo("vendor/nested/deep/d.go")
	writeGo("generated/x.go")

	patterns := []gosec.DirExcludePattern{
		{Pattern: "vendor", Re: gosec.CompileDirExclude("vendor")},
		{Pattern: "generated", Re: gosec.CompileDirExclude("generated")},
	}
	paths, excluded, err := gosec.FindPackagePaths(filepath.Join(root, "..."), patterns)
	if err != nil {
		t.Fatalf("FindPackagePaths: %v", err)
	}
	if len(paths) != 1 {
		t.Errorf("scanned packages = %v, want only the app directory", paths)
	}

	byPattern := map[string][]string{}
	for _, group := range excluded {
		for _, dir := range group.Dirs {
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				t.Fatalf("rel: %v", err)
			}
			byPattern[group.Pattern] = append(byPattern[group.Pattern], filepath.ToSlash(rel))
		}
	}
	want := map[string][]string{
		"vendor":    {"vendor/lib", "vendor/nested/deep"},
		"generated": {"generated"},
	}
	if !reflect.DeepEqual(byPattern, want) {
		t.Errorf("excluded dirs = %v, want %v", byPattern, want)
	}
}

// PackagePaths keeps its old behaviour now that it delegates.
func TestPackagePathsUnchanged(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	paths, err := gosec.PackagePaths(filepath.Join(root, "..."), nil)
	if err != nil {
		t.Fatalf("PackagePaths: %v", err)
	}
	if len(paths) != 1 || paths[0] != root {
		t.Errorf("PackagePaths = %v, want [%s]", paths, root)
	}
}
