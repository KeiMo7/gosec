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

// Package customrules implements declarative, configuration-driven gosec
// rules. Rules are described in YAML files and loaded without rebuilding the
// gosec binary. Every loaded rule is turned into an ordinary gosec.Rule so
// that the reporting, suppression and machine-readable output paths treat
// custom and built-in rules identically.
package customrules

import (
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Anchor kinds supported by declarative rules.
const (
	// AnchorPackageCall matches a function call in a given package,
	// e.g. os/exec.Command.
	AnchorPackageCall = "package_call"
	// AnchorMethodCall matches a method call on a given receiver type,
	// e.g. (*os.File).Chmod.
	AnchorMethodCall = "method_call"
	// AnchorStringLiteral matches string literals whose value matches a
	// regular expression.
	AnchorStringLiteral = "string_literal"
	// AnchorStructTag matches struct field tag values.
	AnchorStructTag = "struct_tag"
)

// Exclusion kinds.
const (
	// ExcludeArgValue suppresses the finding when the argument at the given
	// position holds one of the listed literal values.
	ExcludeArgValue = "arg_value"
	// ExcludeWrapper suppresses the finding when the matched call happens
	// inside one of the listed wrapper functions.
	ExcludeWrapper = "wrapper"
)

// AnchorConfig describes one match location. A rule may declare several
// anchors and fires when any of them matches.
type AnchorConfig struct {
	// Kind is one of package_call, method_call, string_literal, struct_tag.
	Kind string `yaml:"kind"`
	// Package is the import path for package_call anchors
	// (e.g. "os/exec").
	Package string `yaml:"package,omitempty"`
	// Function is the function name for package_call anchors (e.g. "Command").
	Function string `yaml:"function,omitempty"`
	// ReceiverType is the fully qualified receiver type for method_call
	// anchors (e.g. "os/exec.Cmd" or "*os.File").
	ReceiverType string `yaml:"receiver_type,omitempty"`
	// Method is the method name for method_call anchors.
	Method string `yaml:"method,omitempty"`
	// Pattern is the Go regular expression used by string_literal and
	// struct_tag anchors.
	Pattern string `yaml:"pattern,omitempty"`
	// TagKey restricts struct_tag anchors to a specific struct tag key
	// (e.g. "json"). Empty means every tag value is inspected.
	TagKey string `yaml:"tag_key,omitempty"`
	// ArgPosition, when non-nil, restricts call anchors to matches where the
	// argument at this zero-based position originates from an untrusted
	// (non-constant) source.
	ArgPosition *int `yaml:"arg_position,omitempty"`
}

// ExcludeConfig describes a condition under which an otherwise matching rule
// must not fire.
type ExcludeConfig struct {
	// Kind is one of arg_value, wrapper.
	Kind string `yaml:"kind"`
	// ArgPosition is the zero-based call argument position inspected by
	// arg_value exclusions.
	ArgPosition int `yaml:"arg_position"`
	// Values are the literal values that suppress an arg_value exclusion.
	Values []string `yaml:"values,omitempty"`
	// Wrappers lists wrapper function identifiers (local names or fully
	// qualified names such as "main.safeExec") for wrapper exclusions.
	Wrappers []string `yaml:"wrappers,omitempty"`
}

// RuleConfig is a single declarative rule entry.
type RuleConfig struct {
	// ID is the rule identifier (e.g. "G9001"). It must be unique across all
	// loaded custom rule files and must not collide with a built-in rule.
	ID string `yaml:"id"`
	// Description is the human readable explanation carried on every issue.
	Description string `yaml:"description"`
	// Severity is one of low, medium, high.
	Severity string `yaml:"severity"`
	// Confidence is one of low, medium, high.
	Confidence string `yaml:"confidence"`
	// CWE is the CWE ID (digits only, e.g. "78"). An empty value marks the
	// rule as unclassified.
	CWE string `yaml:"cwe,omitempty"`
	// Anchors lists the match locations. At least one anchor is required.
	Anchors []AnchorConfig `yaml:"anchors"`
	// Excludes lists the suppression conditions. It may be empty.
	Excludes []ExcludeConfig `yaml:"excludes,omitempty"`
}

// FileConfig is the top level structure of a custom rule YAML file.
type FileConfig struct {
	// Rules are the rule entries declared by the file.
	Rules []RuleConfig `yaml:"rules"`
}

// LoadError pinpoints an invalid entry and field inside a custom rule file.
// Error messages always carry the source file, the rule index (and, when
// relevant, the anchor or exclude index) and the offending field.
type LoadError struct {
	File    string
	Rule    int
	Anchor  int
	Exclude int
	Field   string
	Reason  string
}

func (e *LoadError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "custom rules %q:", e.File)
	if e.Rule >= 0 {
		fmt.Fprintf(&b, " rules[%d]", e.Rule)
	}
	if e.Anchor >= 0 {
		fmt.Fprintf(&b, ".anchors[%d]", e.Anchor)
	}
	if e.Exclude >= 0 {
		fmt.Fprintf(&b, ".excludes[%d]", e.Exclude)
	}
	if e.Field != "" {
		fmt.Fprintf(&b, ".%s", e.Field)
	}
	fmt.Fprintf(&b, ": %s", e.Reason)
	return b.String()
}

func newLoadError(file string, rule, anchor, exclude int, field, reason string) *LoadError {
	return &LoadError{File: file, Rule: rule, Anchor: anchor, Exclude: exclude, Field: field, Reason: reason}
}

var anchorKinds = map[string]bool{
	AnchorPackageCall:   true,
	AnchorMethodCall:    true,
	AnchorStringLiteral: true,
	AnchorStructTag:     true,
}

var excludeKinds = map[string]bool{
	ExcludeArgValue: true,
	ExcludeWrapper:  true,
}

var validScores = map[string]bool{"low": true, "medium": true, "high": true}

var ruleIDPattern = regexp.MustCompile(`^G[0-9]+$`)

// ParseFile decodes and validates one custom rule file. Unknown YAML fields
// are rejected so that typos fail at load time instead of producing silent
// runtime behaviour. The returned configurations have all regular
// expressions compiled and are ready to be turned into runtime rules.
func ParseFile(fileName string, data []byte) ([]RuleConfig, error) {
	var raw FileConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return nil, newLoadError(fileName, -1, -1, -1, "", fmt.Sprintf("invalid YAML document: %v", err))
	}
	// Decoding a second document must report an explicit error rather than
	// silently dropping rules.
	if decoder.Decode(&FileConfig{}) == nil {
		return nil, newLoadError(fileName, -1, -1, -1, "", "multiple YAML documents are not supported; split extra rules into another file")
	}
	if len(raw.Rules) == 0 {
		return nil, newLoadError(fileName, -1, -1, -1, "rules", "at least one rule entry is required")
	}
	if err := validate(fileName, &raw); err != nil {
		return nil, err
	}
	return raw.Rules, nil
}

func validate(fileName string, raw *FileConfig) error {
	seenIDs := make(map[string]int, len(raw.Rules))
	for rIdx := range raw.Rules {
		rule := &raw.Rules[rIdx]

		if strings.TrimSpace(rule.ID) == "" {
			return newLoadError(fileName, rIdx, -1, -1, "id", "rule id is required")
		}
		if !ruleIDPattern.MatchString(rule.ID) {
			return newLoadError(fileName, rIdx, -1, -1, "id",
				fmt.Sprintf("rule id %q must match G<digits> (e.g. G9001)", rule.ID))
		}
		if first, dup := seenIDs[rule.ID]; dup {
			return newLoadError(fileName, rIdx, -1, -1, "id",
				fmt.Sprintf("duplicate rule id %q; first declared in rules[%d] of this file", rule.ID, first))
		}
		seenIDs[rule.ID] = rIdx

		if strings.TrimSpace(rule.Description) == "" {
			return newLoadError(fileName, rIdx, -1, -1, "description", "rule description is required")
		}
		if !validScores[strings.ToLower(rule.Severity)] {
			return newLoadError(fileName, rIdx, -1, -1, "severity",
				fmt.Sprintf("severity %q is invalid; expected one of low, medium, high", rule.Severity))
		}
		if !validScores[strings.ToLower(rule.Confidence)] {
			return newLoadError(fileName, rIdx, -1, -1, "confidence",
				fmt.Sprintf("confidence %q is invalid; expected one of low, medium, high", rule.Confidence))
		}
		if rule.CWE != "" && !regexp.MustCompile(`^[0-9]+$`).MatchString(rule.CWE) {
			return newLoadError(fileName, rIdx, -1, -1, "cwe",
				fmt.Sprintf("cwe %q must be a numeric CWE id or empty", rule.CWE))
		}
		if len(rule.Anchors) == 0 {
			return newLoadError(fileName, rIdx, -1, -1, "anchors", "at least one anchor is required")
		}

		for aIdx := range rule.Anchors {
			if err := validateAnchor(fileName, rIdx, aIdx, &rule.Anchors[aIdx]); err != nil {
				return err
			}
		}
		for eIdx := range rule.Excludes {
			if err := validateExclude(fileName, rIdx, eIdx, &rule.Excludes[eIdx]); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAnchor(fileName string, ruleIdx, anchorIdx int, anchor *AnchorConfig) error {
	field := func(name, reason string) *LoadError {
		return newLoadError(fileName, ruleIdx, anchorIdx, -1, name, reason)
	}
	if !anchorKinds[anchor.Kind] {
		return field("kind", fmt.Sprintf("unknown anchor kind %q; expected one of %s, %s, %s, %s",
			anchor.Kind, AnchorPackageCall, AnchorMethodCall, AnchorStringLiteral, AnchorStructTag))
	}
	switch anchor.Kind {
	case AnchorPackageCall:
		if strings.TrimSpace(anchor.Package) == "" {
			return field("package", "package is required for package_call anchors")
		}
		if strings.TrimSpace(anchor.Function) == "" {
			return field("function", "function is required for package_call anchors")
		}
		if anchor.ReceiverType != "" || anchor.Method != "" || anchor.Pattern != "" {
			return field("kind", "package_call anchors only accept package, function and arg_position fields")
		}
	case AnchorMethodCall:
		if strings.TrimSpace(anchor.ReceiverType) == "" {
			return field("receiver_type", "receiver_type is required for method_call anchors")
		}
		if strings.TrimSpace(anchor.Method) == "" {
			return field("method", "method is required for method_call anchors")
		}
		if anchor.Package != "" || anchor.Function != "" || anchor.Pattern != "" {
			return field("kind", "method_call anchors only accept receiver_type, method and arg_position fields")
		}
	case AnchorStringLiteral:
		if strings.TrimSpace(anchor.Pattern) == "" {
			return field("pattern", "pattern is required for string_literal anchors")
		}
		if anchor.Package != "" || anchor.Function != "" || anchor.ReceiverType != "" || anchor.Method != "" || anchor.TagKey != "" || anchor.ArgPosition != nil {
			return field("kind", "string_literal anchors only accept the pattern field")
		}
	case AnchorStructTag:
		if strings.TrimSpace(anchor.Pattern) == "" {
			return field("pattern", "pattern is required for struct_tag anchors")
		}
		if anchor.Package != "" || anchor.Function != "" || anchor.ReceiverType != "" || anchor.Method != "" || anchor.ArgPosition != nil {
			return field("kind", "struct_tag anchors only accept pattern and tag_key fields")
		}
	}
	if anchor.ArgPosition != nil && *anchor.ArgPosition < 0 {
		return field("arg_position", "arg_position must be greater than or equal to 0")
	}
	if anchor.Pattern != "" {
		if _, err := regexp.Compile(anchor.Pattern); err != nil {
			return field("pattern", fmt.Sprintf("invalid regular expression: %v", err))
		}
	}
	return nil
}

func validateExclude(fileName string, ruleIdx, excludeIdx int, exclude *ExcludeConfig) error {
	field := func(name, reason string) *LoadError {
		return newLoadError(fileName, ruleIdx, -1, excludeIdx, name, reason)
	}
	if !excludeKinds[exclude.Kind] {
		return field("kind", fmt.Sprintf("unknown exclude kind %q; expected one of %s, %s",
			exclude.Kind, ExcludeArgValue, ExcludeWrapper))
	}
	if exclude.ArgPosition < 0 {
		return field("arg_position", "arg_position must be greater than or equal to 0")
	}
	switch exclude.Kind {
	case ExcludeArgValue:
		if len(exclude.Values) == 0 {
			return field("values", "at least one value is required for arg_value excludes")
		}
		if len(exclude.Wrappers) != 0 {
			return field("wrappers", "wrappers are only valid for wrapper excludes")
		}
	case ExcludeWrapper:
		if len(exclude.Wrappers) == 0 {
			return field("wrappers", "at least one wrapper is required for wrapper excludes")
		}
		if len(exclude.Values) != 0 {
			return field("values", "values are only valid for arg_value excludes")
		}
	}
	return nil
}
