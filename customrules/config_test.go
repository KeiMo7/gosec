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
	"strings"
	"testing"
)

const validRuleYAML = `
rules:
  - id: G9001
    description: test rule
    severity: high
    confidence: medium
    cwe: "78"
    anchors:
      - kind: package_call
        package: os/exec
        function: Command
`

func TestParseFileValid(t *testing.T) {
	rules, err := ParseFile("ok.yaml", []byte(validRuleYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "G9001" {
		t.Fatalf("unexpected rules: %+v", rules)
	}
}

// TestInvalidConfigs covers the six classes of illegal configuration. Every
// error must pinpoint the entry (rule/anchor/exclude index) and the field.
func TestInvalidConfigs(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantField string
		wantHint  string
	}{
		{
			name: "unknown anchor kind",
			yaml: `
rules:
  - id: G9001
    description: x
    severity: low
    confidence: low
    anchors:
      - kind: ast_walk
        package: os
        function: Open
`,
			wantField: "kind",
			wantHint:  "unknown anchor kind",
		},
		{
			name: "argument position out of bounds",
			yaml: `
rules:
  - id: G9001
    description: x
    severity: low
    confidence: low
    anchors:
      - kind: package_call
        package: os/exec
        function: Command
        arg_position: -3
`,
			wantField: "arg_position",
			wantHint:  "greater than or equal to 0",
		},
		{
			name: "illegal regular expression",
			yaml: `
rules:
  - id: G9001
    description: x
    severity: low
    confidence: low
    anchors:
      - kind: string_literal
        pattern: "([a-z"
`,
			wantField: "pattern",
			wantHint:  "invalid regular expression",
		},
		{
			name: "duplicate id within one file",
			yaml: `
rules:
  - id: G9001
    description: x
    severity: low
    confidence: low
    anchors:
      - kind: string_literal
        pattern: "abc"
  - id: G9001
    description: y
    severity: low
    confidence: low
    anchors:
      - kind: string_literal
        pattern: "def"
`,
			wantField: "id",
			wantHint:  "duplicate rule id",
		},
		{
			name: "unknown exclude kind",
			yaml: `
rules:
  - id: G9001
    description: x
    severity: low
    confidence: low
    anchors:
      - kind: package_call
        package: os/exec
        function: Command
    excludes:
      - kind: magic
        arg_position: 0
        values: ["x"]
`,
			wantField: "kind",
			wantHint:  "unknown exclude kind",
		},
		{
			name: "unknown yaml field",
			yaml: `
rules:
  - id: G9001
    description: x
    severity: low
    confidence: low
    sevritey: typo
    anchors:
      - kind: string_literal
        pattern: "abc"
`,
			wantField: "",
			wantHint:  "invalid YAML document",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFile("bad.yaml", []byte(tc.yaml))
			if err == nil {
				t.Fatal("expected a load error, got nil")
			}
			var loadErr *LoadError
			if !errors.As(err, &loadErr) {
				t.Fatalf("expected *LoadError, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "bad.yaml") {
				t.Errorf("error does not name the source file: %v", err)
			}
			// Schema-level errors (unknown YAML field, malformed document) are
			// reported before entries are indexed; the library's line/column
			// detail plays the pinpointing role. Semantic errors carry the
			// rule index.
			if tc.wantField != "" {
				if !strings.Contains(err.Error(), "rules[") {
					t.Errorf("error does not pinpoint the rule entry: %v", err)
				}
			}
			if tc.wantField != "" && loadErr.Field != tc.wantField {
				t.Errorf("expected field %q, got %q (error: %v)", tc.wantField, loadErr.Field, err)
			}
			if !strings.Contains(err.Error(), tc.wantHint) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantHint)
			}
		})
	}
}

func TestParseFileMissingRequiredFields(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantField string
	}{
		{"empty id", "rules:\n  - id: \"\"\n    description: x\n    severity: low\n    confidence: low\n    anchors:\n      - kind: string_literal\n        pattern: a\n", "id"},
		{"bad id format", "rules:\n  - id: X9001\n    description: x\n    severity: low\n    confidence: low\n    anchors:\n      - kind: string_literal\n        pattern: a\n", "id"},
		{"missing description", "rules:\n  - id: G9001\n    description: \"\"\n    severity: low\n    confidence: low\n    anchors:\n      - kind: string_literal\n        pattern: a\n", "description"},
		{"bad severity", "rules:\n  - id: G9001\n    description: x\n    severity: urgent\n    confidence: low\n    anchors:\n      - kind: string_literal\n        pattern: a\n", "severity"},
		{"bad confidence", "rules:\n  - id: G9001\n    description: x\n    severity: low\n    confidence: nope\n    anchors:\n      - kind: string_literal\n        pattern: a\n", "confidence"},
		{"no anchors", "rules:\n  - id: G9001\n    description: x\n    severity: low\n    confidence: low\n    anchors: []\n", "anchors"},
		{"non numeric cwe", "rules:\n  - id: G9001\n    description: x\n    severity: low\n    confidence: low\n    cwe: abc\n    anchors:\n      - kind: string_literal\n        pattern: a\n", "cwe"},
		{"package call missing package", "rules:\n  - id: G9001\n    description: x\n    severity: low\n    confidence: low\n    anchors:\n      - kind: package_call\n        function: Command\n", "package"},
		{"method call missing receiver", "rules:\n  - id: G9001\n    description: x\n    severity: low\n    confidence: low\n    anchors:\n      - kind: method_call\n        method: Chmod\n", "receiver_type"},
		{"string literal missing pattern", "rules:\n  - id: G9001\n    description: x\n    severity: low\n    confidence: low\n    anchors:\n      - kind: string_literal\n        pattern: \"\"\n", "pattern"},
		{"arg value without values", "rules:\n  - id: G9001\n    description: x\n    severity: low\n    confidence: low\n    anchors:\n      - kind: package_call\n        package: os/exec\n        function: Command\n    excludes:\n      - kind: arg_value\n        arg_position: 0\n", "values"},
		{"wrapper without wrappers", "rules:\n  - id: G9001\n    description: x\n    severity: low\n    confidence: low\n    anchors:\n      - kind: package_call\n        package: os/exec\n        function: Command\n    excludes:\n      - kind: wrapper\n        arg_position: 0\n", "wrappers"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFile("bad.yaml", []byte(tc.yaml))
			if err == nil {
				t.Fatal("expected a load error")
			}
			var loadErr *LoadError
			if !errors.As(err, &loadErr) {
				t.Fatalf("expected *LoadError, got %T: %v", err, err)
			}
			if loadErr.Field != tc.wantField {
				t.Fatalf("expected field %q, got %q: %v", tc.wantField, loadErr.Field, err)
			}
		})
	}
}

func TestParseFileRejectsMultipleDocuments(t *testing.T) {
	doc := validRuleYAML + "\n---\n" + validRuleYAML
	_, err := ParseFile("multi.yaml", []byte(doc))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multi-document error, got: %v", err)
	}
}
