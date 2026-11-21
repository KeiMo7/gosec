package review_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/securego/gosec/v2/report/review"
)

// Example shows how one finding appears in the byFile and byRule views, and
// that both carry the same key.
func Example() {
	data, err := os.ReadFile("testdata/demo-review.json")
	if err != nil {
		fmt.Println(err)
		return
	}
	var doc struct {
		Views struct {
			ByFile []struct {
				File      string `json:"file"`
				Functions []struct {
					Name      string `json:"name"`
					Locations []struct {
						Line     int              `json:"line"`
						Column   int              `json:"column"`
						RuleIDs  []string         `json:"ruleIds"`
						Findings []review.Finding `json:"findings"`
					} `json:"locations"`
				} `json:"functions"`
			} `json:"byFile"`
			ByRule []struct {
				RuleID   string           `json:"ruleId"`
				Findings []review.Finding `json:"findings"`
			} `json:"byRule"`
		} `json:"views"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		fmt.Println(err)
		return
	}

	// A statement hit by three different rules: the code view keeps them
	// together.
	var key string
	for _, file := range doc.Views.ByFile {
		for _, fn := range file.Functions {
			for _, loc := range fn.Locations {
				if len(loc.RuleIDs) < 2 {
					continue
				}
				// The file path in the file view is relative to the scan root;
				// the key uses the module-relative path so it stays stable
				// across scan scopes.
				fmt.Printf("byFile   %s %s:%d:%d rules=%s key=%s\n",
					fn.Name, file.File, loc.Line, loc.Column,
					strings.Join(loc.RuleIDs, ","), loc.Findings[0].Key)
				key = loc.Findings[0].Key
			}
		}
	}

	// The same finding is listed under its rule, with the same key.
	for _, group := range doc.Views.ByRule {
		for _, finding := range group.Findings {
			if finding.Key == key {
				fmt.Printf("byRule   %s %s:%d:%d key=%s\n",
					group.RuleID, finding.File, finding.Line, finding.Column, finding.Key)
			}
		}
	}
	// Output:
	// byFile   shared shared.go:6:2 rules=G104,G302,G304 key=G104@app/shared.go:6:2#de64c041
	// byRule   G104 shared.go:6:2 key=G104@app/shared.go:6:2#de64c041
}
