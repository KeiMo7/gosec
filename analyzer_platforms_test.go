package gosec_test

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/rules"
)

// writeFixtureFile writes a file, creating parent directories as needed.
func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newPlatformFixture writes a module with three mutually exclusive platform
// implementations plus one shared insecure call. Each platform-specific file
// has its own finding at a distinct location, and the shared file has a
// finding present on every platform.
func newPlatformFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "go.mod"), "module example.com/platformfixture\n\ngo 1.26\n")
	app := filepath.Join(root, "app")
	writeFixtureFile(t, filepath.Join(app, "common.go"), `package app

import "os"

func Common() { _ = os.Chmod("common", 0777) }
`)
	writeFixtureFile(t, filepath.Join(app, "linux_only.go"), `//go:build linux

package app

import "os"

func LinuxOnly() { _ = os.Chmod("linux", 0777) }
`)
	writeFixtureFile(t, filepath.Join(app, "darwin_only.go"), `//go:build darwin

package app

import "os"

func DarwinOnly() { _ = os.Chmod("darwin", 0777) }
`)
	writeFixtureFile(t, filepath.Join(app, "windows_only.go"), `//go:build windows

package app

import "os"

func WindowsOnly() { _ = os.Chmod("windows", 0777) }
`)
	return root
}

func newPlatformTestAnalyzer(t *testing.T) *gosec.Analyzer {
	t.Helper()
	analyzer := gosec.NewAnalyzer(gosec.NewConfig(), false, false, false, 2, log.New(io.Discard, "", 0))
	analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G302")).RulesInfo())
	return analyzer
}

func TestMultiPlatformAnalyzesMutuallyExclusiveFiles(t *testing.T) {
	t.Parallel()
	root := newPlatformFixture(t)
	app := filepath.Join(root, "app")
	analyzer := newPlatformTestAnalyzer(t)

	selection, err := gosec.SelectPlatforms(gosec.NewConfig(), []string{app},
		[]string{"linux/amd64", "darwin/arm64", "windows/amd64"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := analyzer.ProcessPlatforms(nil, selection, app); err != nil {
		t.Fatal(err)
	}
	issues, _, loadErrors := analyzer.Report()
	if len(loadErrors) != 0 {
		t.Fatalf("unexpected load errors: %v", loadErrors)
	}

	// every platform-specific file must appear in the result
	byFile := map[string][]string{}
	for _, i := range issues {
		byFile[filepath.Base(i.File)] = i.Platforms
	}
	for _, name := range []string{"linux_only.go", "darwin_only.go", "windows_only.go", "common.go"} {
		if _, ok := byFile[name]; !ok {
			t.Fatalf("platform-specific file %s was not analyzed: %v", name, byFile)
		}
	}
	if got := byFile["linux_only.go"]; len(got) != 1 || got[0] != "linux/amd64" {
		t.Fatalf("linux_only.go platforms = %v", got)
	}
	if got := byFile["windows_only.go"]; len(got) != 1 || got[0] != "windows/amd64" {
		t.Fatalf("windows_only.go platforms = %v", got)
	}

	report := analyzer.PlatformReport()
	if report == nil {
		t.Fatal("expected a platform report for a multi-platform run")
	}
	if err := gosec.ValidatePlatformReport(report); err != nil {
		t.Fatalf("invalid platform report: %v", err)
	}
	// 3 shared + 3 exclusive hits across platforms = 6 per-platform hits,
	// merged into 4 distinct issues with 2 duplicates.
	if report.Reconciliation.PerPlatformTotal != 6 ||
		report.Reconciliation.Merged != 4 ||
		report.Reconciliation.Duplicates != 2 {
		t.Fatalf("unexpected reconciliation: %+v", report.Reconciliation)
	}
	if report.Reconciliation.PerPlatformTotal != report.Reconciliation.Merged+report.Reconciliation.Duplicates {
		t.Fatalf("accounting identity does not hold: %+v", report.Reconciliation)
	}
	if !report.Coverage.Complete {
		t.Fatalf("expected complete coverage, missing %v", report.Coverage.Missing)
	}
}

func TestMultiPlatformMergedIssueListsAllPlatforms(t *testing.T) {
	t.Parallel()
	root := newPlatformFixture(t)
	app := filepath.Join(root, "app")
	analyzer := newPlatformTestAnalyzer(t)

	selection, err := gosec.SelectPlatforms(gosec.NewConfig(), []string{app},
		[]string{"linux/amd64", "darwin/arm64", "windows/amd64"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := analyzer.ProcessPlatforms(nil, selection, app); err != nil {
		t.Fatal(err)
	}
	issues, _, _ := analyzer.Report()
	var sharedPlatforms []string
	for _, i := range issues {
		if filepath.Base(i.File) == "common.go" {
			sharedPlatforms = i.Platforms
		}
	}
	if len(sharedPlatforms) != 3 {
		t.Fatalf("shared issue should list all three platforms, got %v", sharedPlatforms)
	}
	// The list must be lossless: it can be used to reconstruct the hits.
	filtered := gosec.FilterIssuesByPlatform(issues, []string{"darwin"})
	if len(filtered) != 2 {
		t.Fatalf("darwin filter should keep the shared and darwin-only issues, got %d", len(filtered))
	}
}

func TestMultiPlatformFailureDoesNotAbortOtherPlatforms(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "go.mod"), "module example.com/brokenplatform\n\ngo 1.26\n")
	app := filepath.Join(root, "app")
	writeFixtureFile(t, filepath.Join(app, "common.go"), `package app

import "os"

func Common() { _ = os.Chmod("common", 0777) }
`)
	writeFixtureFile(t, filepath.Join(app, "darwin_only.go"), `//go:build darwin

package app

import "os"

func DarwinOnly() { _ = os.Chmod("darwin", 0777) }
`)
	// The windows implementation does not compile, so only windows fails.
	writeFixtureFile(t, filepath.Join(app, "windows_only.go"), `//go:build windows

package app

import "os"

func WindowsOnly() { _ = os.Chmod("windows", 0777); undefinedWindowsThing() }
`)

	analyzer := newPlatformTestAnalyzer(t)
	selection, err := gosec.SelectPlatforms(gosec.NewConfig(), []string{app},
		[]string{"linux/amd64", "darwin/arm64", "windows/amd64"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := analyzer.ProcessPlatforms(nil, selection, app); err != nil {
		t.Fatalf("a platform failure must not abort the run: %v", err)
	}

	report := analyzer.PlatformReport()
	if report == nil {
		t.Fatal("expected a platform report")
	}
	if report.Coverage.Complete {
		t.Fatal("coverage should be incomplete when a platform fails")
	}
	if len(report.Coverage.Missing) != 1 || report.Coverage.Missing[0] != "windows/amd64" {
		t.Fatalf("expected windows/amd64 to be missing, got %v", report.Coverage.Missing)
	}
	if len(report.Failed) != 1 || report.Failed[0].Platform != "windows/amd64" {
		t.Fatalf("expected a single failed platform, got %v", report.Failed)
	}
	if err := gosec.ValidatePlatformReport(report); err != nil {
		t.Fatalf("invalid platform report: %v", err)
	}

	// The healthy platforms must still produce their conclusions.
	issues, _, _ := analyzer.Report()
	foundDarwin := false
	for _, i := range issues {
		if filepath.Base(i.File) == "darwin_only.go" {
			foundDarwin = true
		}
	}
	if !foundDarwin {
		t.Fatalf("darwin conclusion missing despite only windows failing: %v", issues)
	}
}

func TestSinglePlatformOutputUnchanged(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "go.mod"), "module example.com/singleplatform\n\ngo 1.26\n")
	writeFixtureFile(t, filepath.Join(root, "main.go"), `package main

import "os"

func main() { _ = os.Chmod("x", 0777) }
`)

	// A plain Process run keeps the historical single-platform behaviour.
	baseline := newPlatformTestAnalyzer(t)
	if err := baseline.Process(nil, root); err != nil {
		t.Fatal(err)
	}
	baselineIssues, _, _ := baseline.Report()
	if baseline.PlatformReport() != nil {
		t.Fatal("a plain scan must not produce a platform report")
	}
	for _, i := range baselineIssues {
		if len(i.Platforms) != 0 {
			t.Fatalf("single-platform issue must not be annotated with platforms: %v", i.Platforms)
		}
	}

	// Explicitly scanning the host platform alone must match exactly.
	host := gosec.HostPlatform()
	selection, err := gosec.SelectPlatforms(gosec.NewConfig(), []string{root}, []string{host.String()}, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostAnalyzer := newPlatformTestAnalyzer(t)
	if err := hostAnalyzer.ProcessPlatforms(nil, selection, root); err != nil {
		t.Fatal(err)
	}
	hostIssues, _, _ := hostAnalyzer.Report()
	if len(hostIssues) != len(baselineIssues) {
		t.Fatalf("host-only issue count changed: %d vs %d", len(hostIssues), len(baselineIssues))
	}
	for idx := range hostIssues {
		b, h := baselineIssues[idx], hostIssues[idx]
		if b.RuleID != h.RuleID || b.File != h.File || b.Line != h.Line || b.Severity != h.Severity || b.Confidence != h.Confidence {
			t.Fatalf("host-only result drifted from baseline at %d: %+v vs %+v", idx, b, h)
		}
		if len(h.Platforms) != 0 {
			t.Fatalf("host-only scan of a single-platform project must not annotate platforms: %v", h.Platforms)
		}
	}
}
