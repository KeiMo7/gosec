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
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// supportedSuffixes are the custom rule file extensions accepted by Load.
var supportedSuffixes = map[string]bool{
	".yaml": true,
	".yml":  true,
}

// Load reads, parses and merges every custom rule file referenced by paths.
// A path may point at a single .yaml/.yml file or at a directory; directories
// are scanned one level deep (non-recursively) for supported files and the
// files are processed in lexical order so that duplicate-id errors are
// deterministic.
//
// Loading is all-or-nothing: any invalid file or any duplicate rule id
// (including collisions with the built-in IDs supplied by the caller) returns
// an error pinpointing the offending entry and field, and no partial rule set
// is returned. No file outside the given paths is read.
func Load(paths []string, builtInIDs map[string]bool) ([]RuleConfig, error) {
	files, err := collectFiles(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("custom rules: no .yaml or .yml rule files found in %v", paths)
	}

	merged := make([]RuleConfig, 0)
	known := make(map[string]string)
	for id := range builtInIDs {
		known[id] = "built-in rule set"
	}

	for _, file := range files {
		data, err := os.ReadFile(file) // #nosec G304 -- paths are operator supplied
		if err != nil {
			return nil, fmt.Errorf("custom rules: cannot read %q: %w", file, err)
		}
		rules, err := ParseFile(file, data)
		if err != nil {
			return nil, err
		}
		for idx, rule := range rules {
			if origin, ok := known[rule.ID]; ok {
				return nil, newLoadError(file, idx, -1, -1, "id",
					fmt.Sprintf("duplicate rule id %q; already defined by %s", rule.ID, origin))
			}
			known[rule.ID] = fmt.Sprintf("%s rules[%d]", file, idx)
			merged = append(merged, rule)
		}
	}
	return merged, nil
}

// collectFiles expands the operator supplied paths into a sorted list of
// supported rule files. Directories are not traversed recursively.
func collectFiles(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("custom rules: cannot access %q: %w", p, err)
		}
		if !info.IsDir() {
			if !supportedSuffixes[filepath.Ext(p)] {
				return nil, fmt.Errorf("custom rules: %q is not a .yaml or .yml file", p)
			}
			files = append(files, p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("custom rules: cannot read directory %q: %w", p, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if supportedSuffixes[filepath.Ext(entry.Name())] {
				files = append(files, filepath.Join(p, entry.Name()))
			}
		}
	}
	sort.Strings(files)
	return files, nil
}
