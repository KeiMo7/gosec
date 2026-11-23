// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package customrules_test

import (
	"log"
	"testing"
	"time"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/customrules"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/testutils"
)

// eightRulesYAML is the acceptance fixture: eight declarative rules covering
// every anchor kind and every exclusion condition.
const eightRulesYAML = `
rules:
  - id: G9001
    description: package call anchor fires on os/exec.Command
    severity: high
    confidence: high
    cwe: "78"
    anchors:
      - kind: package_call
        package: os/exec
        function: Command

  - id: G9002
    description: method call anchor fires on (*os.File).Chmod
    severity: medium
    confidence: high
    cwe: "732"
    anchors:
      - kind: method_call
        receiver_type: "*os.File"
        method: Chmod

  - id: G9003
    description: string literal anchor matches token-like values
    severity: high
    confidence: medium
    cwe: "798"
    anchors:
      - kind: string_literal
        pattern: "token-[a-z0-9]+"

  - id: G9004
    description: struct tag anchor matches insecure db tags
    severity: medium
    confidence: medium
    cwe: "89"
    anchors:
      - kind: struct_tag
        tag_key: db
        pattern: "password"

  - id: G9005
    description: untrusted argument position on exec.Command
    severity: high
    confidence: high
    cwe: "78"
    anchors:
      - kind: package_call
        package: os/exec
        function: Command
        arg_position: 0

  - id: G9006
    description: multi anchor rule fires on either anchor
    severity: medium
    confidence: medium
    cwe: "20"
    anchors:
      - kind: package_call
        package: os
        function: RemoveAll
      - kind: string_literal
        pattern: "dangerous-literal"

  - id: G9007
    description: arg value exclusion suppresses safe command names
    severity: high
    confidence: high
    cwe: "78"
    anchors:
      - kind: package_call
        package: os/exec
        function: Command
    excludes:
      - kind: arg_value
        arg_position: 0
        values: ["ls", "whoami"]

  - id: G9008
    description: wrapper exclusion suppresses calls inside safeExec
    severity: high
    confidence: high
    cwe: "78"
    anchors:
      - kind: package_call
        package: os/exec
        function: Command
    excludes:
      - kind: wrapper
        arg_position: 0
        wrappers: ["safeExec", "main.safeExec"]
`

const sampleGo = `package main

import (
	"os"
	"os/exec"
)

const constName = "ls"

type tagged struct {
	User     string ` + "`db:\"user_name\"`" + `
	Password string ` + "`db:\"password\" json:\"password\"`" + `
	Note     string ` + "`json:\"note\"`" + `
}

func safeExec(name string) *exec.Cmd {
	return exec.Command(name, "-l") // G9008 suppressed: inside wrapper
}

func run(userInput string) error {
	// G9001, G9005, G9007 (not in exclude list), G9008 (not inside wrapper)
	cmd := exec.Command(userInput, "-arg")
	_ = cmd

	// G9001 fires; G9005 does not (constant); G9007 excluded by value
	litCmd := exec.Command("ls", "-l")
	_ = litCmd

	// G9001 fires; G9005 does not (const identifier resolves)
	constCmd := exec.Command(constName, "-l")
	_ = constCmd

	// G9008 suppressed, G9007 fires ("cat" not excluded)
	wrapped := safeExec("cat")
	_ = wrapped

	f, err := os.Open("/tmp/x")
	if err != nil {
		return err
	}
	// G9002 fires
	defer f.Chmod(0o777)

	// G9003 fires
	secret := "token-abc123"
	_ = secret

	// G9003 does not fire
	plain := "just a sentence"
	_ = plain

	// G9006 fires via string anchor
	_ = "dangerous-literal"

	// G9006 fires via package call
	return os.RemoveAll("/tmp/dir")
}
`

func loadEightRules(t *testing.T) map[string]gosec.RuleBuilder {
	t.Helper()
	customrules.ResetStats()
	configs, err := customrules.ParseFile("eight.yaml", []byte(eightRulesYAML))
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	builders, err := customrules.Builder(configs)
	if err != nil {
		t.Fatalf("build rules: %v", err)
	}
	for _, cfg := range configs {
		issue.RegisterRuleCWE(cfg.ID, cfg.CWE)
	}
	return builders
}

func runAnalyzer(t *testing.T, builders map[string]gosec.RuleBuilder) ([]*issue.Issue, *gosec.Metrics) {
	t.Helper()
	logger := log.New(log.Writer(), "[test] ", 0)
	customrules.SetLogger(logger)
	analyzer := gosec.NewAnalyzer(gosec.NewConfig(), false, false, false, 1, logger)
	analyzer.LoadRules(builders, map[string]bool{})

	pkg := testutils.NewTestPackage()
	defer pkg.Close()
	pkg.AddFile("sample.go", sampleGo)
	if err := pkg.Build(); err != nil {
		t.Fatalf("build sample: %v", err)
	}
	if pkg.PrintErrors() != 0 {
		t.Fatal("sample package has type errors")
	}
	if err := analyzer.Process(nil, pkg.Path); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	issues, metrics, errs := analyzer.Report()
	if len(errs) != 0 {
		t.Fatalf("analyzer errors: %v", errs)
	}
	return issues, metrics
}

func issueCounts(issues []*issue.Issue) map[string]int {
	counts := make(map[string]int)
	for _, iss := range issues {
		counts[iss.RuleID]++
	}
	return counts
}

// TestEightRulesAcceptance asserts each of the eight rules fires exactly the
// number of times the annotated sample predicts, covering every anchor and
// exclusion condition required by the acceptance plan.
func TestEightRulesAcceptance(t *testing.T) {
	builders := loadEightRules(t)
	issues, metrics := runAnalyzer(t, builders)
	counts := issueCounts(issues)

	expected := map[string]int{
		"G9001": 4, // three direct Command calls + one inside safeExec
		"G9002": 1, // f.Chmod
		"G9003": 1, // token-abc123 only
		"G9004": 1, // Password field db tag
		"G9005": 2, // userInput call and the safeExec parameter call are untrusted
		"G9006": 2, // string literal + os.RemoveAll
		"G9007": 2, // userInput and cat; ls and constName(ls) excluded
		"G9008": 3, // three calls outside safeExec; the wrapper one suppressed
	}
	if len(counts) != len(expected) {
		t.Fatalf("expected rules %v, got counts %v", expected, counts)
	}
	for id, want := range expected {
		if got := counts[id]; got != want {
			t.Errorf("rule %s: expected %d findings, got %d (all counts: %v)", id, want, got, counts)
		}
	}
	if metrics.NumFound != len(issues) {
		t.Errorf("metrics NumFound=%d but %d issues reported", metrics.NumFound, len(issues))
	}
	total := 0
	for _, n := range expected {
		total += n
	}
	if len(issues) != total {
		t.Errorf("expected %d total findings, got %d", total, len(issues))
	}
}

// TestCustomIssueMetadata verifies severity, confidence, description and CWE
// all come from the configuration and travel through the ordinary issue path.
func TestCustomIssueMetadata(t *testing.T) {
	builders := loadEightRules(t)
	issues, _ := runAnalyzer(t, builders)
	var found *issue.Issue
	for _, iss := range issues {
		if iss.RuleID == "G9001" {
			found = iss
			break
		}
	}
	if found == nil {
		t.Fatal("G9001 did not fire")
	}
	if found.Severity != issue.High || found.Confidence != issue.High {
		t.Errorf("unexpected scores: severity=%s confidence=%s", found.Severity, found.Confidence)
	}
	if found.What != "package call anchor fires on os/exec.Command" {
		t.Errorf("description not sourced from config: %q", found.What)
	}
	if found.Cwe == nil || found.Cwe.ID != "78" {
		t.Errorf("expected CWE-78 from config, got %+v", found.Cwe)
	}
}

// TestUnclassifiedPlaceholder covers the missing-classification fallback.
func TestUnclassifiedPlaceholder(t *testing.T) {
	customrules.ResetStats()
	yaml := `
rules:
  - id: G9100
    description: rule without CWE
    severity: low
    confidence: low
    anchors:
      - kind: string_literal
        pattern: "unclassified-token"
`
	configs, err := customrules.ParseFile("nocwe.yaml", []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	builders, err := customrules.Builder(configs)
	if err != nil {
		t.Fatal(err)
	}
	issue.RegisterRuleCWE("G9100", "")
	path := writeSamplePackage(t, "nocwe.go", `package main

var _ = "unclassified-token"
`)
	logger := log.New(log.Writer(), "[test] ", 0)
	customrules.SetLogger(logger)
	analyzer := gosec.NewAnalyzer(gosec.NewConfig(), false, false, false, 1, logger)
	analyzer.LoadRules(builders, map[string]bool{})
	if err := analyzer.Process(nil, path); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	issues, _, _ := analyzer.Report()
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if !issue.IsUnclassified(issues[0].Cwe) {
		t.Fatalf("expected unclassified placeholder, got %+v", issues[0].Cwe)
	}
	snap := customrules.StatsSnapshot()
	for _, s := range snap {
		if s.RuleID == "G9100" && s.Unclassified != 1 {
			t.Fatalf("expected unclassified counter 1, got %+v", s)
		}
	}
}

// TestAnchorMissCounter verifies that anchors referencing symbols absent from
// the scanned code are counted rather than interrupting the scan.
func TestAnchorMissCounter(t *testing.T) {
	customrules.ResetStats()
	yaml := `
rules:
  - id: G9200
    description: references a package the sample never imports
    severity: low
    confidence: low
    cwe: "20"
    anchors:
      - kind: package_call
        package: net/http
        function: Get
      - kind: method_call
        receiver_type: "*net/http.Client"
        method: Do
`
	configs, err := customrules.ParseFile("miss.yaml", []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	builders, err := customrules.Builder(configs)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range configs {
		issue.RegisterRuleCWE(cfg.ID, cfg.CWE)
	}
	issues, _ := runAnalyzer(t, builders)
	if len(issues) != 0 {
		t.Fatalf("absent anchors must not produce findings, got %d", len(issues))
	}
	var miss int64
	for _, s := range customrules.StatsSnapshot() {
		if s.RuleID == "G9200" {
			miss = s.AnchorMiss
		}
	}
	if miss != 2 {
		t.Fatalf("expected 2 anchor misses (package + method), got %d", miss)
	}
}

// TestRegexTimeout verifies a runaway pattern is skipped and counted. The
// eval hook blocks the evaluation goroutine past the configured budget so the
// test is deterministic and does not depend on RE2 wall-clock behaviour.
func TestRegexTimeout(t *testing.T) {
	customrules.ResetStats()
	yaml := `
rules:
  - id: G9300
    description: pattern whose evaluation exceeds the budget
    severity: low
    confidence: low
    cwe: "20"
    anchors:
      - kind: string_literal
        pattern: "token-[a-z0-9]+"
`
	configs, err := customrules.ParseFile("timeout.yaml", []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	builders, err := customrules.Builder(configs)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range configs {
		issue.RegisterRuleCWE(cfg.ID, cfg.CWE)
	}

	customrules.SetRegexTimeoutForTest(5 * time.Millisecond)
	defer customrules.SetRegexTimeoutForTest(0)
	customrules.SetEvalHookForTest(func(string) {
		time.Sleep(50 * time.Millisecond)
	})
	defer customrules.SetEvalHookForTest(nil)

	path := writeSamplePackage(t, "timeout.go", `package main

var _ = "token-abc123"
`)
	logger := log.New(log.Writer(), "[test] ", 0)
	analyzer := gosec.NewAnalyzer(gosec.NewConfig(), false, false, false, 1, logger)
	analyzer.LoadRules(builders, map[string]bool{})
	if err := analyzer.Process(nil, path); err != nil {
		t.Fatalf("scan must not be interrupted by regex timeout: %v", err)
	}
	issues, _, _ := analyzer.Report()
	if len(issues) != 0 {
		t.Fatalf("timed-out rule must be skipped, got %d issues", len(issues))
	}
	var timeouts int64
	for _, s := range customrules.StatsSnapshot() {
		if s.RuleID == "G9300" {
			timeouts = s.RegexTimeouts
		}
	}
	if timeouts == 0 {
		t.Fatal("expected at least one regex timeout counter")
	}
}

func writeSamplePackage(t *testing.T, filename, code string) string {
	t.Helper()
	pkg := testutils.NewTestPackage()
	t.Cleanup(pkg.Close)
	pkg.AddFile(filename, code)
	if err := pkg.Build(); err != nil {
		t.Fatal(err)
	}
	if pkg.PrintErrors() != 0 {
		t.Fatal("sample package has type errors")
	}
	return pkg.Path
}
