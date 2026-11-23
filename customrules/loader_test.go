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

package customrules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempRules(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func ruleYAML(id string) string {
	return `
rules:
  - id: ` + id + `
    description: rule ` + id + `
    severity: medium
    confidence: medium
    anchors:
      - kind: string_literal
        pattern: "token-"
`
}

func TestLoadMergesMultipleFiles(t *testing.T) {
	first := writeTempRules(t, "a.yaml", ruleYAML("G9001"))
	second := writeTempRules(t, "b.yml", ruleYAML("G9002"))
	merged, err := Load([]string{first, second}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged rules, got %d", len(merged))
	}
}

func TestLoadFromDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(ruleYAML("G9001")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(ruleYAML("G9002")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	merged, err := Load([]string{dir}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("directory loading must be non-recursive, got %d rules", len(merged))
	}
}

func TestLoadRejectsDuplicateAcrossFiles(t *testing.T) {
	first := writeTempRules(t, "a.yaml", ruleYAML("G9001"))
	second := writeTempRules(t, "b.yaml", ruleYAML("G9001"))
	_, err := Load([]string{first, second}, nil)
	if err == nil {
		t.Fatal("expected duplicate id error")
	}
	if !strings.Contains(err.Error(), "duplicate rule id \"G9001\"") {
		t.Fatalf("error should name the duplicated id: %v", err)
	}
	var loadErr *LoadError
	if !errors.As(err, &loadErr) || loadErr.Field != "id" {
		t.Fatalf("error must pinpoint the id field: %v", err)
	}
}

func TestLoadRejectsBuiltInCollision(t *testing.T) {
	path := writeTempRules(t, "builtin.yaml", ruleYAML("G101"))
	_, err := Load([]string{path}, map[string]bool{"G101": true})
	if err == nil || !strings.Contains(err.Error(), "already defined by built-in rule set") {
		t.Fatalf("expected built-in collision error, got: %v", err)
	}
}

func TestLoadRejectsUnsupportedExtension(t *testing.T) {
	path := writeTempRules(t, "rules.txt", ruleYAML("G9001"))
	_, err := Load([]string{path}, nil)
	if err == nil || !strings.Contains(err.Error(), "not a .yaml or .yml file") {
		t.Fatalf("expected extension error, got: %v", err)
	}
}

func TestLoadMissingPath(t *testing.T) {
	_, err := Load([]string{filepath.Join(t.TempDir(), "missing.yaml")}, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot access") {
		t.Fatalf("expected access error, got: %v", err)
	}
}

func TestBuilderRejectsInvalidConfig(t *testing.T) {
	// Builder assumes validated input; an uncompilable pattern still fails loudly.
	_, err := Builder([]RuleConfig{{
		ID:          "G9001",
		Description: "x",
		Severity:    "low",
		Confidence:  "low",
		Anchors: []AnchorConfig{{
			Kind:    AnchorStringLiteral,
			Pattern: "([",
		}},
	}})
	if err == nil {
		t.Fatal("expected builder error for bad pattern")
	}
}
