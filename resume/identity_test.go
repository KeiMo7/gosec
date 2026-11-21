package resume

import (
	"os"
	"path/filepath"
	"testing"
)

const pkgSource = `package pkg

import "crypto/md5"

func Weak(data []byte) [16]byte {
	return md5.Sum(data)
}
`

// TestIdentityStableAcrossCheckouts proves the package key contains no
// absolute-path component: the same module layout checked out at two
// different roots produces the same key and identity.
func TestIdentityStableAcrossCheckouts(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	checkoutA := filepath.Join(base, "checkout-a")
	checkoutB := filepath.Join(base, "checkout-b")
	writeModule(t, checkoutA, "example.com/project",
		map[string]string{filepath.Join("sub", "pkg", "weak.go"): pkgSource})
	writeModule(t, checkoutB, "example.com/project",
		map[string]string{filepath.Join("sub", "pkg", "weak.go"): pkgSource})

	planner := NewPlanner(nil, false)
	planA, err := planner.PlanPackage(filepath.Join(checkoutA, "sub", "pkg"))
	if err != nil {
		t.Fatal(err)
	}
	planB, err := planner.PlanPackage(filepath.Join(checkoutB, "sub", "pkg"))
	if err != nil {
		t.Fatal(err)
	}
	if planA.Key != planB.Key {
		t.Fatalf("keys differ across checkouts: %s vs %s", planA.Key, planB.Key)
	}
	if planA.Identity != planB.Identity {
		t.Fatalf("identities differ: %q vs %q", planA.Identity, planB.Identity)
	}
	wantIdentity := "example.com/project:sub/pkg"
	if planA.Identity != wantIdentity {
		t.Fatalf("identity = %q, want %q", planA.Identity, wantIdentity)
	}
	if planA.Fingerprint != planB.Fingerprint {
		t.Fatal("identical content should hash identically")
	}
}

func TestFingerprintChangesWithContentAndModuleFiles(t *testing.T) {
	t.Parallel()
	moduleRoot := filepath.Join(t.TempDir(), "mod")
	pkgDir := filepath.Join(moduleRoot, "pkg")
	writeModule(t, moduleRoot, "example.com/m",
		map[string]string{filepath.Join("pkg", "a.go"): "package pkg\nfunc A() int { return 1 }\n"})
	planner := NewPlanner(nil, false)

	before, err := planner.PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}

	// Changing a package file changes the fingerprint.
	if err := os.WriteFile(filepath.Join(pkgDir, "a.go"),
		[]byte("package pkg\nfunc A() int { return 2 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterFile, err := planner.PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	if afterFile.Fingerprint == before.Fingerprint {
		t.Fatal("fingerprint must change when a Go file changes")
	}
	if afterFile.Key != before.Key {
		t.Fatal("identity must stay stable when content changes")
	}

	// Changing go.mod (dependency context) also invalidates the fingerprint.
	if err := os.WriteFile(filepath.Join(moduleRoot, "go.mod"),
		[]byte("module example.com/m\n\ngo 1.23\nrequire x v1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterMod, err := planner.PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	if afterMod.Fingerprint == afterFile.Fingerprint {
		t.Fatal("fingerprint must change when go.mod changes")
	}
}

func TestNewPackageIsRescannedAfterChange(t *testing.T) {
	t.Parallel()
	moduleRoot := filepath.Join(t.TempDir(), "mod")
	pkgDir := filepath.Join(moduleRoot, "pkg")
	writeModule(t, moduleRoot, "example.com/m",
		map[string]string{filepath.Join("pkg", "a.go"): "package pkg\nfunc A() int { return 1 }\n"})
	planner := NewPlanner(nil, false)
	plan, err := planner.PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}

	state := filepath.Join(t.TempDir(), "state")
	store, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if store.Decide(plan).Reuse {
		t.Fatal("unseen package must not be reused")
	}
	if _, err := store.Record(plan, StateCompleted, []byte("[]"), nil, Stats{Files: 1}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !store.Decide(plan).Reuse {
		t.Fatal("completed, unchanged package should be reused")
	}

	// Add a second package in the same module; it must be planned as new
	// while the first one stays reusable.
	pkg2Dir := filepath.Join(moduleRoot, "pkg2")
	if err := os.MkdirAll(pkg2Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg2Dir, "b.go"),
		[]byte("package pkg2\nfunc B() int { return 2 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan2, err := planner.PlanPackage(pkg2Dir)
	if err != nil {
		t.Fatal(err)
	}
	if store.Decide(plan2).Reuse {
		t.Fatal("newly added package must not be reused")
	}
	if !store.Decide(plan).Reuse {
		t.Fatal("unchanged package must still be reused")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNoGoPackageIsMarkedAndStable(t *testing.T) {
	t.Parallel()
	moduleRoot := filepath.Join(t.TempDir(), "mod")
	emptyDir := filepath.Join(moduleRoot, "empty")
	writeModule(t, moduleRoot, "example.com/m", nil)
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	planner := NewPlanner(nil, false)
	plan, err := planner.PlanPackage(emptyDir)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.NoGo {
		t.Fatal("directory without Go files should be flagged NoGo")
	}
}

func TestBuildTagsSelectFingerprintFiles(t *testing.T) {
	t.Parallel()
	moduleRoot := filepath.Join(t.TempDir(), "mod")
	pkgDir := filepath.Join(moduleRoot, "pkg")
	writeModule(t, moduleRoot, "example.com/m", map[string]string{
		filepath.Join("pkg", "a.go"):   "package pkg\nfunc A() int { return 1 }\n",
		filepath.Join("pkg", "tag.go"): "//go:build integration\n\npackage pkg\nfunc Tagged() int { return 2 }\n",
	})
	plain := NewPlanner(nil, false)
	tagged := NewPlanner([]string{"integration"}, false)

	planPlain, err := plain.PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	planTagged, err := tagged.PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	if planPlain.Fingerprint == planTagged.Fingerprint {
		t.Fatal("build tags change the files participating in the build and must change the fingerprint")
	}
	if planPlain.Key != planTagged.Key {
		t.Fatal("build tags must not change package identity")
	}
}

func TestAdHocSameNamedDirectoriesDoNotCollide(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	// Two packages with the same base name in different locations and no
	// go.mod anywhere above them.
	dirA := filepath.Join(base, "tree-a", "svc")
	dirB := filepath.Join(base, "tree-b", "svc")
	for _, dir := range []string{dirA, dirB} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "f.go"),
			[]byte("package svc\nfunc F() int { return 1 }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	planner := NewPlanner(nil, false)
	planA, err := planner.PlanPackage(dirA)
	if err != nil {
		t.Fatal(err)
	}
	planB, err := planner.PlanPackage(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if planA.Key == planB.Key {
		t.Fatal("same-named ad-hoc packages in different locations must have distinct keys")
	}
}

func TestTestsFlagControlsTestFileFingerprint(t *testing.T) {
	t.Parallel()
	moduleRoot := filepath.Join(t.TempDir(), "mod")
	pkgDir := filepath.Join(moduleRoot, "pkg")
	writeModule(t, moduleRoot, "example.com/m", map[string]string{
		filepath.Join("pkg", "a.go"):      "package pkg\nfunc A() int { return 1 }\n",
		filepath.Join("pkg", "a_test.go"): "package pkg\nfunc TestA(t *testing.T) {}\n",
	})

	withoutTests, err := NewPlanner(nil, false).PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	withTests, err := NewPlanner(nil, true).PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	if withoutTests.Fingerprint == withTests.Fingerprint {
		t.Fatal("enabling test scanning must pull _test.go files into the fingerprint")
	}
	if withoutTests.Key != withTests.Key {
		t.Fatal("the tests flag must not change package identity")
	}

	// With tests disabled, editing a test file does not change the fingerprint.
	if err := os.WriteFile(filepath.Join(pkgDir, "a_test.go"),
		[]byte("package pkg\nfunc TestA(t *testing.T) { println(1) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := NewPlanner(nil, false).PlanPackage(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Fingerprint != withoutTests.Fingerprint {
		t.Fatal("test file edits must not invalidate a scan that excludes tests")
	}
}
