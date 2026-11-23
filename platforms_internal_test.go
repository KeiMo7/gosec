package gosec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securego/gosec/v2/issue"
)

func TestParsePlatformsRequiresFullValidNames(t *testing.T) {
	got, err := ParsePlatforms([]string{"linux/amd64", "windows", "linux/amd64"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected de-duplicated list, got %v", got)
	}
	if got[0].String() != "linux/amd64" {
		t.Fatalf("unexpected first platform: %s", got[0])
	}
	if got[1].GOOS != "windows" || got[1].GOARCH == "" {
		t.Fatalf("GOOS-only platform was not resolved to an architecture: %v", got[1])
	}

	for _, bad := range []string{"linux/amd64/extra", "plan9/amd64/extra", "notanos", "linux/invalidarch"} {
		if _, err := ParsePlatforms([]string{bad}); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

func TestParsePlatformsAcceptsSerializedList(t *testing.T) {
	got, err := ParsePlatforms([]string{"[linux/amd64 darwin/arm64]"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two platforms, got %v", got)
	}
}

func TestSelectPlatformsExplicitWins(t *testing.T) {
	selection, err := SelectPlatforms(NewConfig(), nil, []string{"darwin/arm64"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if selection.Source != PlatformSourceExplicit {
		t.Fatalf("source = %q, want explicit", selection.Source)
	}
	if len(selection.Platforms) != 1 || selection.Platforms[0].String() != "darwin/arm64" {
		t.Fatalf("unexpected platforms: %v", selection.Platforms)
	}
	if selection.Message != "" {
		t.Fatalf("explicit in-budget selection should not warn: %q", selection.Message)
	}
}

func TestSelectPlatformsFromConfig(t *testing.T) {
	config := NewConfig()
	config.Set(PlatformKey, []interface{}{"linux/amd64", "windows/amd64"})
	selection, err := SelectPlatforms(config, nil, nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if selection.Source != PlatformSourceExplicit || len(selection.Platforms) != 2 {
		t.Fatalf("config list not honored: %+v", selection)
	}
}

func TestSelectPlatformsInvalidConfigFails(t *testing.T) {
	config := NewConfig()
	config.Set(PlatformKey, "notanos")
	if _, err := SelectPlatforms(config, nil, nil, 0); err == nil {
		t.Fatal("expected invalid configured platform to be rejected")
	}
}

func TestSelectPlatformsClipsToBudgetAndReports(t *testing.T) {
	selection, err := SelectPlatforms(NewConfig(), nil,
		[]string{"linux/amd64", "darwin/arm64", "windows/amd64", "freebsd/amd64"}, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(selection.Platforms) != 2 {
		t.Fatalf("expected budget of 2, got %v", selection.Platforms)
	}
	if len(selection.Excluded) != 2 {
		t.Fatalf("expected 2 excluded platforms, got %v", selection.Excluded)
	}
	if !strings.Contains(selection.Message, "dropped") {
		t.Fatalf("clipping must be reported, got %q", selection.Message)
	}
}

func TestSelectPlatformsHostFallbackIsSilentWhenNoDimension(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	selection, err := SelectPlatforms(NewConfig(), []string{dir}, nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if selection.Source != PlatformSourceHost || len(selection.Platforms) != 1 {
		t.Fatalf("unexpected selection: %+v", selection)
	}
	if selection.Platforms[0] != HostPlatform() {
		t.Fatalf("expected the host platform, got %v", selection.Platforms)
	}
	// A project with no platform dimension must not produce a warning that
	// would differ from a single-platform run.
	if selection.Message != "" {
		t.Fatalf("unexpected message: %q", selection.Message)
	}
}

func TestInferPlatformsFromBuildConstraints(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("common.go", "package app\n")
	write("linux.go", "//go:build linux\n\npackage app\n")
	write("platform_darwin.go", "package app\n")
	write("freebsd_only.go", "//go:build freebsd\n\npackage app\n")
	write("special.go", "//go:build !windows\n\npackage app\n")

	platforms, declared := InferPlatforms([]string{dir})
	if !declared {
		t.Fatal("expected a declared platform dimension")
	}
	names := make(map[string]bool)
	for _, p := range platforms {
		names[p.GOOS] = true
	}
	// linux comes from the constraint, darwin from the file suffix, freebsd
	// from the constraint on an ordinary file name.
	if !names["linux"] || !names["darwin"] || !names["freebsd"] {
		t.Fatalf("expected linux, darwin and freebsd to be inferred, got %v", platforms)
	}
	if names["windows"] {
		t.Fatalf("a negated constraint must not declare windows: %v", platforms)
	}
}

func TestInferPlatformsNoDimension(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	platforms, declared := InferPlatforms([]string{dir})
	if declared || len(platforms) != 0 {
		t.Fatalf("expected no platform dimension, got %v (declared=%v)", platforms, declared)
	}
}

func TestConfigPlatformKeys(t *testing.T) {
	config := NewConfig()
	config.Set(PlatformKey, "linux/amd64,darwin/arm64")
	config.Set(MaxPlatformsKey, float64(3))
	config.Set(InferPlatformsKey, "disabled")

	platforms, err := config.GetPlatforms()
	if err != nil || len(platforms) != 2 {
		t.Fatalf("platforms = %v, err = %v", platforms, err)
	}
	maxPlatforms, err := config.GetMaxPlatforms()
	if err != nil || maxPlatforms != 3 {
		t.Fatalf("max platforms = %d, err = %v", maxPlatforms, err)
	}
	if config.PlatformInferenceEnabled() {
		t.Fatal("inference should be disabled")
	}
}

func TestConfigPlatformKeysUnderGlobals(t *testing.T) {
	config := NewConfig()
	globals := config[Globals].(map[GlobalOption]string)
	globals[GlobalOption(PlatformKey)] = "[windows/amd64 linux/amd64]"

	platforms, err := config.GetPlatforms()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(platforms) != 2 {
		t.Fatalf("expected two platforms, got %v", platforms)
	}
}

func TestMergePlatformResults(t *testing.T) {
	linux := Platform{GOOS: "linux", GOARCH: "amd64"}
	windows := Platform{GOOS: "windows", GOARCH: "amd64"}
	shared := &issue.Issue{RuleID: "G302", File: "common.go", Line: "5", Col: "2", What: "perm", Severity: issue.High, Confidence: issue.High}
	linuxOnly := &issue.Issue{RuleID: "G302", File: "linux.go", Line: "7", Col: "2", What: "perm", Severity: issue.High, Confidence: issue.High}
	windowsOnly := &issue.Issue{RuleID: "G302", File: "windows.go", Line: "7", Col: "2", What: "perm", Severity: issue.High, Confidence: issue.High}

	merged, stats := mergePlatformResults(map[Platform][]*issue.Issue{
		linux:   {shared, linuxOnly},
		windows: {shared, windowsOnly},
	}, PlatformSet{linux, windows})

	if len(merged) != 3 {
		t.Fatalf("expected 3 merged issues, got %d", len(merged))
	}
	byFile := map[string]*issue.Issue{}
	for _, i := range merged {
		byFile[i.File] = i
	}
	if got := byFile["common.go"].Platforms; len(got) != 2 {
		t.Fatalf("shared issue should list both platforms, got %v", got)
	}
	if got := byFile["linux.go"].Platforms; len(got) != 1 || got[0] != "linux/amd64" {
		t.Fatalf("linux-only issue platforms = %v", got)
	}
	report := &PlatformReport{Stats: stats}
	report.reconcile()
	if err := ValidatePlatformReport(report); err != nil {
		t.Fatalf("reconciliation invalid: %v", err)
	}
	if report.Reconciliation.PerPlatformTotal != 4 ||
		report.Reconciliation.Merged != 3 ||
		report.Reconciliation.Duplicates != 1 {
		t.Fatalf("unexpected reconciliation: %+v", report.Reconciliation)
	}
}

func TestMergePlatformResultsSeverityIsNotCollapsed(t *testing.T) {
	linux := Platform{GOOS: "linux", GOARCH: "amd64"}
	windows := Platform{GOOS: "windows", GOARCH: "amd64"}
	low := &issue.Issue{RuleID: "G999", File: "x.go", Line: "1", Col: "1", What: "w", Severity: issue.Low, Confidence: issue.Low}
	high := &issue.Issue{RuleID: "G999", File: "x.go", Line: "1", Col: "1", What: "w", Severity: issue.High, Confidence: issue.High}

	merged, _ := mergePlatformResults(map[Platform][]*issue.Issue{
		linux:   {low},
		windows: {high},
	}, PlatformSet{linux, windows})
	if len(merged) != 2 {
		t.Fatalf("the same location with different severity must not collapse, got %d", len(merged))
	}
}

func TestFilterIssuesByPlatform(t *testing.T) {
	shared := &issue.Issue{RuleID: "G1", File: "a.go", Platforms: []string{"linux/amd64", "windows/amd64"}}
	linuxOnly := &issue.Issue{RuleID: "G2", File: "b.go", Platforms: []string{"linux/amd64"}}
	unknown := &issue.Issue{RuleID: "G3", File: "c.go"}

	filtered := FilterIssuesByPlatform([]*issue.Issue{shared, linuxOnly, unknown}, []string{"windows"})
	if len(filtered) != 2 || filtered[0] != shared || filtered[1] != unknown {
		t.Fatalf("unexpected filter result: %v", filtered)
	}
	if got := FilterIssuesByPlatform([]*issue.Issue{shared}, nil); len(got) != 1 {
		t.Fatal("empty platform list must not filter")
	}
}

func TestValidatePlatformReportRejectsImbalance(t *testing.T) {
	report := &PlatformReport{Stats: []PlatformStats{{Platform: "linux/amd64", Issues: 2, Unique: 1, Duplicates: 0}}}
	report.reconcile()
	if err := ValidatePlatformReport(report); err == nil {
		t.Fatal("expected the unbalanced report to be rejected")
	}
}

func TestDetectVerdictConflicts(t *testing.T) {
	linux := Platform{GOOS: "linux", GOARCH: "amd64"}
	windows := Platform{GOOS: "windows", GOARCH: "amd64"}
	agreeLow := &issue.Issue{RuleID: "G999", File: "a.go", Line: "1", Col: "1", What: "w", Severity: issue.Low, Confidence: issue.High}
	agreeLow2 := &issue.Issue{RuleID: "G999", File: "a.go", Line: "1", Col: "1", What: "w", Severity: issue.Low, Confidence: issue.High}
	disagree := &issue.Issue{RuleID: "G999", File: "b.go", Line: "1", Col: "1", What: "w", Severity: issue.High, Confidence: issue.High}

	conflicts := detectVerdictConflicts(map[Platform][]*issue.Issue{
		linux:   {agreeLow, disagree},
		windows: {agreeLow2, disagree},
	}, PlatformSet{linux, windows})
	if len(conflicts) != 0 {
		t.Fatalf("consistent verdicts must not conflict: %+v", conflicts)
	}

	conflicts = detectVerdictConflicts(map[Platform][]*issue.Issue{
		linux:   {agreeLow},
		windows: {&issue.Issue{RuleID: "G999", File: "a.go", Line: "1", Col: "1", What: "w", Severity: issue.High, Confidence: issue.High}},
	}, PlatformSet{linux, windows})
	if len(conflicts) != 1 {
		t.Fatalf("expected one conflict, got %+v", conflicts)
	}
	if len(conflicts[0].Platforms) != 2 {
		t.Fatalf("conflict should name both platforms: %+v", conflicts[0])
	}
}
