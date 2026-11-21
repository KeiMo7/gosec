package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeScanFixture creates a small module with a directory that has to be
// excluded from the scan.
func writeScanFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, content string) {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("go.mod", "module fixture\n\ngo 1.26\n")
	write("app/main.go", `package app

import (
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
)

func risky(name string) {
	fmt.Println(md5.New())
	cmd := exec.Command("sh", "-c", name)
	_ = cmd.Run()
	_, _ = os.Open(name)
}

func many() {
	_ = md5.New()
	_ = md5.New()
	_ = md5.New()
}
`)
	write("app/perm.go", `package app

import "os"

func perm(name string) {
	os.OpenFile(name, os.O_RDWR, 0666)
}
`)
	write("vendor/lib/v.go", `package lib

import "crypto/md5"

func v() { _ = md5.New() }
`)
	return root
}

var (
	buildOnce   sync.Once
	builtBinary string
	buildErr    error
)

// gosecBinary builds the CLI once per test process, so repeated runs do not
// pay the link cost (and do not fill the temporary directory with copies).
func gosecBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		builtBinary = filepath.Join(os.TempDir(), fmt.Sprintf("gosec-cli-%d", os.Getpid()))
		build := exec.Command("go", "build", "-o", builtBinary, ".")
		build.Dir = "."
		if out, err := build.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build gosec: %v\n%s", err, out)
			return
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return builtBinary
}

// runGosecBinary runs the CLI with the given arguments, working from the
// fixture root so relative paths in the report are meaningful.
func runGosecBinary(t *testing.T, dir string, args ...string) (stdout, stderr []byte, code int) {
	t.Helper()
	cmd := exec.Command(gosecBinary(t), args...)
	cmd.Dir = dir
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code = 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run gosec: %v\n%s", err, errOut.String())
		}
	}
	return out.Bytes(), errOut.Bytes(), code
}

// TestMain removes the shared CLI binary once the package's tests finish.
func TestMain(m *testing.M) {
	code := m.Run()
	if builtBinary != "" {
		_ = os.Remove(builtBinary)
	}
	os.Exit(code)
}

func asExitError(err error, target **exec.ExitError) bool {
	if exitErr, ok := err.(*exec.ExitError); ok {
		*target = exitErr
		return true
	}
	return false
}

// The review report has to be byte-identical across two runs of the same scan,
// and it has to name the directory that was excluded.
func TestReviewReportIsDeterministicAndNamesExclusions(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and runs the CLI")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	root := writeScanFixture(t)

	scan := func(report string) []byte {
		_, stderr, _ := runGosecBinary(t, root, "-quiet", "-concurrency", "4",
			"-exclude-dir", "vendor",
			"-review-report", report, "-review-format", "json", "./...")
		data, err := os.ReadFile(report)
		if err != nil {
			t.Fatalf("read review report: %v\n%s", err, stderr)
		}
		return data
	}

	first := scan(filepath.Join(root, "first.json"))
	second := scan(filepath.Join(root, "second.json"))
	if !bytes.Equal(first, second) {
		t.Fatalf("review reports differ between runs:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}

	var doc map[string]any
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if strings.Contains(string(first), root) {
		t.Fatalf("report contains the absolute scan root %q", root)
	}

	excluded, _ := doc["excluded"].([]any)
	if len(excluded) != 1 {
		t.Fatalf("expected one excluded pattern, got %v", doc["excluded"])
	}
	entry := excluded[0].(map[string]any)
	if entry["pattern"] != "vendor" {
		t.Errorf("excluded pattern = %v, want vendor", entry["pattern"])
	}
	dirs, _ := entry["dirs"].([]any)
	if len(dirs) != 1 || dirs[0] != "vendor/lib" {
		t.Errorf("excluded dirs = %v, want [vendor/lib]", dirs)
	}

	// The same rule firing several times in one function keeps every hit.
	found := map[string]int{}
	for _, layer := range doc["views"].(map[string]any)["bySeverity"].([]any) {
		for _, f := range layer.(map[string]any)["findings"].([]any) {
			finding := f.(map[string]any)
			found[finding["ruleId"].(string)]++
		}
	}
	if found["G401"] < 4 {
		t.Errorf("expected the repeated G401 hits to survive grouping, got %v", found)
	}
	if found["G204"] == 0 || found["G304"] == 0 {
		t.Errorf("expected G204 and G304 findings, got %v", found)
	}
}

// Without the new flags the existing output format and exit code must not
// change.
func TestReviewReportOffKeepsLegacyBehaviour(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and runs the CLI")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	root := writeScanFixture(t)

	stdout, stderr, code := runGosecBinary(t, root, "-quiet", "-fmt", "json", "./...")
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout, &doc); err != nil {
		t.Fatalf("legacy JSON output is not valid JSON: %v\n%s\n%s", err, stdout, stderr)
	}
	if _, ok := doc["Issues"]; !ok {
		t.Fatalf("legacy JSON output lost its Issues field: %s", stdout)
	}
	if _, ok := doc["views"]; ok {
		t.Fatalf("legacy JSON output unexpectedly contains review views")
	}
	if !strings.Contains(string(stdout), root) {
		t.Fatalf("legacy JSON output should keep absolute file paths, got: %s", stdout)
	}
}

// A review report written next to the output file must not disturb the
// regular report produced by the same invocation.
func TestReviewReportDoesNotChangeExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and runs the CLI")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	root := writeScanFixture(t)
	report := filepath.Join(root, "review.json")

	_, _, withReview := runGosecBinary(t, root, "-quiet", "-review-report", report, "-review-format", "json", "./...")
	_, _, withoutReview := runGosecBinary(t, root, "-quiet", "./...")
	if withReview != withoutReview {
		t.Fatalf("exit code changed when the review report was enabled: %d vs %d", withReview, withoutReview)
	}
	if _, err := os.Stat(report); err != nil {
		t.Fatalf("review report was not written: %v", err)
	}
}

// When the review report is enabled but the regular output was also asked for,
// the regular output must still be complete rather than empty.
func TestReviewReportKeepsRegularOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and runs the CLI")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	root := writeScanFixture(t)

	regular, _, _ := runGosecBinary(t, root, "-quiet", "-fmt", "json", "./...")
	withReviewOut, stderr, _ := runGosecBinary(t, root, "-quiet", "-fmt", "json",
		"-review-report", filepath.Join(root, "review.json"), "-review-format", "json", "./...")
	var legacy, withReview map[string]any
	if err := json.Unmarshal(regular, &legacy); err != nil {
		t.Fatalf("legacy JSON output invalid: %v\n%s", err, regular)
	}
	if err := json.Unmarshal(withReviewOut, &withReview); err != nil {
		t.Fatalf("regular JSON output with review enabled invalid: %v\n%s\n%s", err, withReviewOut, stderr)
	}
	legacyIssues, ok := legacy["Issues"].([]any)
	if !ok || len(legacyIssues) == 0 {
		t.Fatalf("legacy run produced no issues: %v", legacy["Issues"])
	}
	reviewIssues, ok := withReview["Issues"].([]any)
	if !ok {
		t.Fatalf("regular output with review enabled lost its Issues field: %s", withReviewOut)
	}
	if len(reviewIssues) != len(legacyIssues) {
		t.Fatalf("regular output changed with review enabled: %d issues vs %d", len(reviewIssues), len(legacyIssues))
	}
	// Code snippets, severities and line ranges must survive the round trip.
	firstLegacy := legacyIssues[0].(map[string]any)
	firstReview := reviewIssues[0].(map[string]any)
	for _, field := range []string{"file", "line", "column", "rule_id", "severity", "confidence", "code"} {
		if firstLegacy[field] != firstReview[field] {
			t.Errorf("field %q changed with review enabled: %v vs %v", field, firstLegacy[field], firstReview[field])
		}
	}
}

// An unwritable review destination has to be rejected before the scan starts.
func TestReviewReportUnwritableTargetFailsFast(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	root := writeScanFixture(t)
	_, stderr, code := runGosecBinary(t, root,
		"-review-report", filepath.Join(root, "no-such-dir", "review.json"), "./...")
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(string(stderr), "review report") {
		t.Fatalf("expected an error about the review report target, got: %s", stderr)
	}
}
