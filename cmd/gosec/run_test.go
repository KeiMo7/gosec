package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/securego/gosec/v2/cmd/vflag"
)

func TestRun_NoInputReturnsFailure(t *testing.T) {
	t.Parallel()

	code := runInSubprocess(t, "no-input")
	if code != exitFailure {
		t.Fatalf("unexpected exit code: got %d want %d", code, exitFailure)
	}
}

func TestRun_VersionReturnsSuccess(t *testing.T) {
	t.Parallel()

	code := runInSubprocess(t, "version")
	if code != exitSuccess {
		t.Fatalf("unexpected exit code: got %d want %d", code, exitSuccess)
	}
}

func runInSubprocess(t *testing.T, scenario string) int {
	return runInSubprocessEnv(t, scenario, nil)
}

func runInSubprocessEnv(t *testing.T, scenario string, env []string) int {
	t.Helper()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to resolve test executable: %v", err)
	}

	cmd := exec.Command(executable, "-test.run=^TestRunHelperProcess$")
	cmd.Env = append(os.Environ(), "GOSEC_RUN_HELPER=1", "GOSEC_RUN_SCENARIO="+scenario)
	cmd.Env = append(cmd.Env, env...)

	err = cmd.Run()
	if err == nil {
		return 0
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("failed to run helper process: %v", err)
	}

	return exitErr.ExitCode()
}

func TestRunHelperProcess(t *testing.T) {
	_ = t

	if os.Getenv("GOSEC_RUN_HELPER") != "1" {
		return
	}

	scenario := os.Getenv("GOSEC_RUN_SCENARIO")

	flag.CommandLine = flag.NewFlagSet("gosec-helper", flag.ContinueOnError)
	os.Args = []string{"gosec"}

	*flagIgnoreNoSec = false
	*flagShowIgnored = false
	*flagAlternativeNoSec = ""
	*flagEnableAudit = false
	*flagOutput = ""
	*flagConfig = ""
	*flagQuiet = true
	*flagRulesInclude = ""
	flagRulesExclude = vflag.ValidatedFlag{}
	*flagExcludeGenerated = false
	*flagLogfile = ""
	*flagSortIssues = true
	*flagBuildTags = ""
	*flagSeverity = "low"
	*flagConfidence = "low"
	*flagNoFail = false
	*flagScanTests = false
	*flagVersion = false
	*flagStdOut = false
	*flagColor = false
	*flagRecursive = false
	*flagVerbose = ""
	*flagTrackSuppressions = false
	*flagTerse = false
	*flagPlatforms = ""
	*flagMaxPlatforms = 4
	*flagPlatformFilter = ""
	*flagNoInferPlatforms = false
	*flagAiAPIProvider = ""
	*flagAiAPIKey = ""
	*flagAiBaseURL = ""
	*flagAiSkipSSL = false
	flagDirsExclude = nil

	if scenario == "version" {
		*flagVersion = true
	}
	if scenario == "platforms" {
		*flagQuiet = true
		*flagFormat = "json"
		*flagOutput = os.Getenv("GOSEC_RUN_OUT")
		*flagPlatforms = os.Getenv("GOSEC_RUN_PLATFORMS")
		os.Args = []string{"gosec", os.Getenv("GOSEC_RUN_TARGET")}
	}

	os.Exit(run())
}

// writePlatformFixture writes a module with mutually exclusive platform files.
func writePlatformFixture(t *testing.T, brokenWindows bool) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/cliplatform\n\ngo 1.26\n")
	write("app/common.go", "package app\n\nimport \"os\"\n\nfunc Common() { _ = os.Chmod(\"c\", 0777) }\n")
	write("app/linux_only.go", "//go:build linux\n\npackage app\n\nimport \"os\"\n\nfunc LinuxOnly() { _ = os.Chmod(\"l\", 0777) }\n")
	write("app/darwin_only.go", "//go:build darwin\n\npackage app\n\nimport \"os\"\n\nfunc DarwinOnly() { _ = os.Chmod(\"d\", 0777) }\n")
	windows := "package app\n\nimport \"os\"\n\nfunc WindowsOnly() { _ = os.Chmod(\"w\", 0777) }\n"
	if brokenWindows {
		windows = "package app\n\nimport \"os\"\n\nfunc WindowsOnly() { _ = os.Chmod(\"w\", 0777); undefinedWindowsThing() }\n"
	}
	write("app/windows_only.go", "//go:build windows\n\n"+windows)
	return root
}

func TestRun_MultiPlatformReportAndExitCode(t *testing.T) {
	t.Parallel()

	root := writePlatformFixture(t, false)
	out := filepath.Join(t.TempDir(), "out.json")
	code := runInSubprocessEnv(t, "platforms", []string{
		"GOSEC_RUN_TARGET=" + filepath.Join(root, "app"),
		"GOSEC_RUN_PLATFORMS=linux/amd64,darwin/arm64,windows/amd64",
		"GOSEC_RUN_OUT=" + out,
	})
	// Findings exist, so the exit code is the ordinary failure code.
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Issues    []map[string]any `json:"Issues"`
		Platforms struct {
			Platforms []string `json:"platforms"`
			Coverage  struct {
				Complete bool `json:"complete"`
			} `json:"coverage"`
			Reconciliation struct {
				PerPlatformTotal int  `json:"per_platform_total"`
				Merged           int  `json:"merged"`
				Duplicates       int  `json:"duplicates"`
				Balanced         bool `json:"balanced"`
			} `json:"reconciliation"`
		} `json:"platforms"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Platforms.Platforms) != 3 {
		t.Fatalf("expected three platforms, got %v", decoded.Platforms.Platforms)
	}
	if !decoded.Platforms.Coverage.Complete {
		t.Fatal("coverage should be complete")
	}
	recon := decoded.Platforms.Reconciliation
	if recon.PerPlatformTotal != recon.Merged+recon.Duplicates || !recon.Balanced {
		t.Fatalf("reconciliation does not balance: %+v", recon)
	}
	// all four files must produce a finding somewhere in the merged set
	files := map[string]bool{}
	for _, i := range decoded.Issues {
		name := filepath.Base(i["file"].(string))
		files[name] = true
		if _, ok := i["platforms"]; !ok {
			t.Fatalf("multi-platform issue lacks the platforms annotation: %v", i)
		}
	}
	for _, name := range []string{"common.go", "linux_only.go", "darwin_only.go", "windows_only.go"} {
		if !files[name] {
			t.Fatalf("file %s missing from the merged result: %v", name, files)
		}
	}
}

func TestRun_IncompletePlatformCoverageExitsIncomplete(t *testing.T) {
	t.Parallel()

	root := writePlatformFixture(t, true)
	out := filepath.Join(t.TempDir(), "out.json")
	code := runInSubprocessEnv(t, "platforms", []string{
		"GOSEC_RUN_TARGET=" + filepath.Join(root, "app"),
		"GOSEC_RUN_PLATFORMS=linux/amd64,darwin/arm64,windows/amd64",
		"GOSEC_RUN_OUT=" + out,
	})
	if code != exitIncomplete {
		t.Fatalf("exit code = %d, want %d for incomplete coverage", code, exitIncomplete)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Platforms struct {
			Coverage struct {
				Complete bool     `json:"complete"`
				Missing  []string `json:"missing"`
			} `json:"coverage"`
			Failed []struct {
				Platform string `json:"platform"`
			} `json:"failed"`
		} `json:"platforms"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Platforms.Coverage.Complete {
		t.Fatal("coverage should be incomplete")
	}
	if len(decoded.Platforms.Coverage.Missing) != 1 || decoded.Platforms.Coverage.Missing[0] != "windows/amd64" {
		t.Fatalf("unexpected missing platforms: %v", decoded.Platforms.Coverage.Missing)
	}
	if len(decoded.Platforms.Failed) != 1 || decoded.Platforms.Failed[0].Platform != "windows/amd64" {
		t.Fatalf("unexpected failed platforms: %v", decoded.Platforms.Failed)
	}
}
