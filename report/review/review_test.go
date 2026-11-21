package review_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/report/review"
)

// testRoot is the scan root used by every fixture. Findings are fed to the
// builder through a sink just as the analyzer would deliver them.
// makeRoot writes a small source tree so the report can resolve the enclosing
// function of a finding, and returns the root.
func makeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

func newBuilder(t *testing.T, format review.Format, roots ...string) (*review.Builder, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "review."+string(format))
	if len(roots) == 0 {
		roots = []string{"/repo"}
	}
	b, err := review.New(review.Options{
		OutputPath:    out,
		Format:        format,
		Roots:         roots,
		MinSeverity:   issue.Low,
		MinConfidence: issue.Low,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(b.Close)
	return b, out
}

func mkIssue(file, line, col, rule string, severity issue.Score, what string) *issue.Issue {
	return &issue.Issue{
		File:       file,
		Line:       line,
		Col:        col,
		RuleID:     rule,
		Severity:   severity,
		Confidence: issue.High,
		What:       what,
	}
}

func writeAndFinalize(t *testing.T, b *review.Builder, out string, issues []*issue.Issue, summary review.Summary) []byte {
	t.Helper()
	for _, iss := range issues {
		if err := b.WriteIssue(iss); err != nil {
			t.Fatalf("WriteIssue: %v", err)
		}
	}
	if err := b.Finalize(summary); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	return data
}

// decodeReport parses the JSON report into generic maps for assertions.
func decodeReport(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, data)
	}
	return doc
}

func functionsOf(t *testing.T, doc map[string]any, file string) map[string][]map[string]any {
	t.Helper()
	views := doc["views"].(map[string]any)
	for _, entry := range views["byFile"].([]any) {
		f := entry.(map[string]any)
		if f["file"] != file {
			continue
		}
		result := map[string][]map[string]any{}
		for _, fnEntry := range f["functions"].([]any) {
			fn := fnEntry.(map[string]any)
			name := fn["name"].(string)
			for _, locEntry := range fn["locations"].([]any) {
				result[name] = append(result[name], locEntry.(map[string]any))
			}
		}
		return result
	}
	t.Fatalf("file %q not found in byFile view", file)
	return nil
}

// A single rule firing three times inside one function must be reported three
// times, each at its own statement.
func TestSameRuleMultipleHitsInOneFunction(t *testing.T) {
	root := makeRoot(t, map[string]string{
		"pkg/a.go": "package pkg\n\nimport \"crypto/md5\"\n\nfunc many() {\n\t_ = md5.New()\n\t_ = md5.New()\n\t_ = md5.New()\n}\n",
	})
	b, out := newBuilder(t, review.FormatJSON, root)
	file := filepath.Join(root, "pkg/a.go")
	issues := []*issue.Issue{
		mkIssue(file, "6", "6", "G401", issue.Medium, "weak primitive"),
		mkIssue(file, "7", "6", "G401", issue.Medium, "weak primitive"),
		mkIssue(file, "8", "6", "G401", issue.Medium, "weak primitive"),
	}
	data := writeAndFinalize(t, b, out, issues, review.Summary{NumFiles: 1, NumLines: 10})
	doc := decodeReport(t, data)

	funcs := functionsOf(t, doc, "pkg/a.go")
	locs := funcs["many"]
	if len(locs) != 3 {
		t.Fatalf("expected 3 locations for function many, got %d: %v", len(locs), locs)
	}
	for i, want := range []float64{6, 7, 8} {
		if locs[i]["line"] != want {
			t.Errorf("location %d line = %v, want %v", i, locs[i]["line"], want)
		}
	}

	// The rule view must keep all three, still traceable to file and line.
	var g401 []map[string]any
	for _, g := range doc["views"].(map[string]any)["byRule"].([]any) {
		group := g.(map[string]any)
		if group["ruleId"] == "G401" {
			if group["count"] != float64(3) {
				t.Errorf("G401 count = %v, want 3", group["count"])
			}
			for _, f := range group["findings"].([]any) {
				g401 = append(g401, f.(map[string]any))
			}
		}
	}
	if len(g401) != 3 {
		t.Fatalf("expected 3 G401 findings in rule view, got %d", len(g401))
	}
	if g401[0]["file"] != "pkg/a.go" || g401[0]["line"] != float64(6) {
		t.Errorf("first G401 finding not traceable: %v", g401[0])
	}
}

// Two rules hitting the same statement must be grouped together so a reviewer
// sees both at once, and both must still appear in their own rule groups.
func TestMultipleRulesAtSameLocationAreGrouped(t *testing.T) {
	root := makeRoot(t, map[string]string{
		"pkg/a.go": "package pkg\n\nimport \"os\"\n\nfunc both(name string) {\n\t_ = name\n\tos.OpenFile(name, os.O_RDWR, 0666)\n}\n",
	})
	b, out := newBuilder(t, review.FormatJSON, root)
	file := filepath.Join(root, "pkg/a.go")
	issues := []*issue.Issue{
		mkIssue(file, "7", "2", "G304", issue.Medium, "file inclusion"),
		mkIssue(file, "7", "2", "G302", issue.Medium, "file permissions"),
		mkIssue(file, "7", "2", "G104", issue.Low, "errors unhandled"),
	}
	data := writeAndFinalize(t, b, out, issues, review.Summary{})
	doc := decodeReport(t, data)

	funcs := functionsOf(t, doc, "pkg/a.go")
	locs := funcs["both"]
	if len(locs) != 1 {
		t.Fatalf("expected the three rules to share one location, got %d locations: %v", len(locs), locs)
	}
	loc := locs[0]
	rules := toStrings(loc["ruleIds"])
	want := []string{"G104", "G302", "G304"}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("ruleIds at the shared location = %v, want %v", rules, want)
	}
	if n := len(loc["findings"].([]any)); n != 3 {
		t.Errorf("shared location has %d findings, want 3", n)
	}

	for _, rule := range want {
		found := false
		for _, g := range doc["views"].(map[string]any)["byRule"].([]any) {
			if g.(map[string]any)["ruleId"] == rule {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %s missing from the cross-file rule view", rule)
		}
	}
}

// The rule view aggregates the same rule across files while each entry keeps
// its file and line.
func TestCrossFileRuleAggregation(t *testing.T) {
	b, out := newBuilder(t, review.FormatJSON)
	issues := []*issue.Issue{
		mkIssue("/repo/a/x.go", "3", "9", "G401", issue.Medium, "weak primitive"),
		mkIssue("/repo/b/y.go", "7", "1", "G401", issue.Medium, "weak primitive"),
		mkIssue("/repo/c/z.go", "12", "5", "G401", issue.Medium, "weak primitive"),
	}
	data := writeAndFinalize(t, b, out, issues, review.Summary{})
	doc := decodeReport(t, data)

	group := findRuleGroup(t, doc, "G401")
	if group["count"] != float64(3) {
		t.Fatalf("G401 count = %v, want 3", group["count"])
	}
	var got []string
	for _, f := range group["findings"].([]any) {
		finding := f.(map[string]any)
		got = append(got, finding["file"].(string))
	}
	if want := []string{"a/x.go", "b/y.go", "c/z.go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("cross-file order = %v, want %v", got, want)
	}
}

// A directory removed from the scan is named in the report, so the absence of
// findings there is not mistaken for a clean scan.
func TestExcludedDirectoryIsReported(t *testing.T) {
	out := filepath.Join(t.TempDir(), "review.txt")
	b, err := review.New(review.Options{
		OutputPath: out,
		Format:     review.FormatText,
		Roots:      []string{"/repo"},
		Excluded: []review.Exclusion{
			{Pattern: "vendor", Total: 2, Dirs: []string{"vendor/lib", "vendor/gen"}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer b.Close()
	data := writeAndFinalize(t, b, out, nil, review.Summary{NumFiles: 3, NumLines: 30})
	text := string(data)

	for _, want := range []string{
		"Excluded from the scan:",
		"vendor (2 directories)",
		"vendor/lib",
		"vendor/gen",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("excluded directory report missing %q:\n%s", want, text)
		}
	}
}

// Running the same scan twice must produce byte-identical output, even when
// the findings arrive in a different order (concurrency).
func TestReportIsByteIdenticalAcrossRuns(t *testing.T) {
	base := []*issue.Issue{
		mkIssue("/repo/a/x.go", "3", "9", "G401", issue.Medium, "weak primitive"),
		mkIssue("/repo/a/x.go", "4", "9", "G401", issue.Medium, "weak primitive"),
		mkIssue("/repo/b/y.go", "7", "1", "G204", issue.High, "subprocess"),
		mkIssue("/repo/b/y.go", "7", "1", "G304", issue.Medium, "file inclusion"),
		mkIssue("/repo/c/z.go", "12", "5", "G104", issue.Low, "errors unhandled"),
	}

	run := func(issues []*issue.Issue) []byte {
		b, out := newBuilder(t, review.FormatJSON)
		return writeAndFinalize(t, b, out, issues, review.Summary{NumFiles: 3, NumLines: 40})
	}

	first := run(base)
	shuffled := append([]*issue.Issue(nil), base...)
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].File > shuffled[j].File })
	second := run(shuffled)

	if string(first) != string(second) {
		t.Fatalf("reports differ between runs of the same scan:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}

	// Text output has to be stable too.
	runText := func(issues []*issue.Issue) []byte {
		b, out := newBuilder(t, review.FormatText)
		return writeAndFinalize(t, b, out, issues, review.Summary{NumFiles: 3, NumLines: 40})
	}
	if a, c := runText(base), runText(shuffled); string(a) != string(c) {
		t.Fatalf("text reports differ between runs:\n--- first ---\n%s\n--- second ---\n%s", a, c)
	}
}

// Severity layers must come out HIGH, MEDIUM, LOW and each layer must keep a
// stable order of its own.
func TestSeverityLayersAreOrderedAndStable(t *testing.T) {
	issues := []*issue.Issue{
		mkIssue("/repo/a.go", "30", "1", "G104", issue.Low, "low a"),
		mkIssue("/repo/a.go", "10", "1", "G204", issue.High, "high a"),
		mkIssue("/repo/a.go", "20", "1", "G304", issue.Medium, "medium a"),
		mkIssue("/repo/b.go", "5", "1", "G204", issue.High, "high b"),
		mkIssue("/repo/b.go", "6", "1", "G104", issue.Low, "low b"),
		mkIssue("/repo/b.go", "7", "1", "G304", issue.Medium, "medium b"),
	}

	render := func(order []int) []byte {
		ordered := make([]*issue.Issue, 0, len(issues))
		for _, i := range order {
			ordered = append(ordered, issues[i])
		}
		b, out := newBuilder(t, review.FormatJSON)
		return writeAndFinalize(t, b, out, ordered, review.Summary{})
	}

	forward := render([]int{0, 1, 2, 3, 4, 5})
	reverse := render([]int{5, 4, 3, 2, 1, 0})
	if string(forward) != string(reverse) {
		t.Fatalf("severity view depends on arrival order:\n--- forward ---\n%s\n--- reverse ---\n%s", forward, reverse)
	}

	doc := decodeReport(t, forward)
	layers := doc["views"].(map[string]any)["bySeverity"].([]any)
	if len(layers) != 3 {
		t.Fatalf("expected 3 severity layers, got %d", len(layers))
	}
	wantOrder := []string{"HIGH", "MEDIUM", "LOW"}
	for i, want := range wantOrder {
		layer := layers[i].(map[string]any)
		if layer["severity"] != want {
			t.Errorf("layer %d = %v, want %v", i, layer["severity"], want)
		}
	}

	// Inside a layer findings are ordered by file then line.
	high := layers[0].(map[string]any)["findings"].([]any)
	var got []string
	for _, f := range high {
		finding := f.(map[string]any)
		got = append(got, finding["file"].(string)+":"+jsonNumber(finding["line"]))
	}
	if want := []string{"a.go:10", "b.go:5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("HIGH layer order = %v, want %v", got, want)
	}
}

// Keys must identify a finding independently of the scan it came from.
func TestKeysAreStableAcrossScanSubsets(t *testing.T) {
	full := []*issue.Issue{
		mkIssue("/repo/a.go", "3", "9", "G401", issue.Medium, "weak primitive"),
		mkIssue("/repo/b.go", "7", "1", "G204", issue.High, "subprocess"),
		mkIssue("/repo/c.go", "12", "5", "G104", issue.Low, "errors unhandled"),
	}
	keysFor := func(issues []*issue.Issue) map[string]string {
		b, out := newBuilder(t, review.FormatJSON)
		data := writeAndFinalize(t, b, out, issues, review.Summary{})
		doc := decodeReport(t, data)
		keys := map[string]string{}
		for _, layer := range doc["views"].(map[string]any)["bySeverity"].([]any) {
			for _, f := range layer.(map[string]any)["findings"].([]any) {
				finding := f.(map[string]any)
				keys[finding["file"].(string)+":"+jsonNumber(finding["line"])] = finding["key"].(string)
			}
		}
		return keys
	}

	all := keysFor(full)
	subset := keysFor([]*issue.Issue{full[2], full[0]}) // same scan repackaged, other order and subset

	for location, key := range subset {
		if all[location] != key {
			t.Errorf("key for %s changed between scan subsets: %q vs %q", location, all[location], key)
		}
	}
	if got := len(all); got != 3 {
		t.Fatalf("expected 3 keys, got %d", got)
	}
	for location, key := range all {
		if strings.Contains(key, "/repo/") {
			t.Errorf("key for %s contains an absolute path: %q", location, key)
		}
		if !strings.HasPrefix(key, "G") {
			t.Errorf("key for %s should start with the rule ID: %q", location, key)
		}
	}
}

// Absolute paths must never leak into the report.
func TestPathsAreRelativeToScanRoot(t *testing.T) {
	b, out := newBuilder(t, review.FormatJSON)
	issues := []*issue.Issue{
		mkIssue("/repo/internal/app/main.go", "3", "9", "G401", issue.Medium, "weak primitive"),
	}
	data := writeAndFinalize(t, b, out, issues, review.Summary{})
	if strings.Contains(string(data), "/repo/") {
		t.Fatalf("report contains an absolute path:\n%s", data)
	}
	doc := decodeReport(t, data)
	fileEntry := doc["views"].(map[string]any)["byFile"].([]any)[0].(map[string]any)
	if fileEntry["file"] != "internal/app/main.go" {
		t.Errorf("file = %v, want internal/app/main.go", fileEntry["file"])
	}
}

// Suppressed findings and findings below the configured threshold are counted
// but not listed, mirroring the regular report.
func TestSuppressedAndFilteredFindings(t *testing.T) {
	b, out := newBuilder(t, review.FormatJSON)
	suppressed := mkIssue("/repo/a.go", "1", "1", "G401", issue.Medium, "weak primitive")
	suppressed.Suppressions = []issue.SuppressionInfo{{Kind: "inline", Justification: "known"}}
	issues := []*issue.Issue{
		suppressed,
		mkIssue("/repo/a.go", "2", "1", "G401", issue.Medium, "weak primitive"),
	}
	data := writeAndFinalize(t, b, out, issues, review.Summary{})
	doc := decodeReport(t, data)
	stats := doc["stats"].(map[string]any)
	if stats["findings"] != float64(1) {
		t.Errorf("findings = %v, want 1", stats["findings"])
	}
	if stats["suppressed"] != float64(1) {
		t.Errorf("suppressed = %v, want 1", stats["suppressed"])
	}

	b2, out2 := newBuilder(t, review.FormatJSON)
	low := mkIssue("/repo/a.go", "3", "1", "G104", issue.Low, "errors unhandled")
	// Re-create the builder with a HIGH confidence threshold.
	b3, err := review.New(review.Options{
		OutputPath:    filepath.Join(filepath.Dir(out2), "filtered.json"),
		Format:        review.FormatJSON,
		Roots:         []string{"/repo"},
		MinSeverity:   issue.Medium,
		MinConfidence: issue.Low,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer b3.Close()
	defer b2.Close()
	data2, err := func() ([]byte, error) {
		if err := b3.WriteIssue(low); err != nil {
			return nil, err
		}
		if err := b3.Finalize(review.Summary{}); err != nil {
			return nil, err
		}
		return os.ReadFile(filepath.Join(filepath.Dir(out2), "filtered.json"))
	}()
	if err != nil {
		t.Fatalf("filtered report: %v", err)
	}
	doc2 := decodeReport(t, data2)
	stats2 := doc2["stats"].(map[string]any)
	if stats2["findings"] != float64(0) {
		t.Errorf("filtered findings = %v, want 0", stats2["findings"])
	}
	if stats2["filteredByThreshold"] != float64(1) {
		t.Errorf("filteredByThreshold = %v, want 1", stats2["filteredByThreshold"])
	}
}

// An unwritable destination must be rejected before any scanning.
func TestNewRejectsUnwritableTarget(t *testing.T) {
	dir := t.TempDir()
	if _, err := review.New(review.Options{
		OutputPath: filepath.Join(dir, "missing", "report.json"),
		Format:     review.FormatJSON,
	}); err == nil {
		t.Fatal("expected an error for a missing output directory")
	}
	if _, err := review.New(review.Options{
		OutputPath: dir, // a directory, not a file
		Format:     review.FormatJSON,
	}); err == nil {
		t.Fatal("expected an error when the output path is a directory")
	}
	if _, err := review.New(review.Options{
		OutputPath: filepath.Join(dir, "r.json"),
		Format:     "xml",
	}); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func findRuleGroup(t *testing.T, doc map[string]any, ruleID string) map[string]any {
	t.Helper()
	for _, g := range doc["views"].(map[string]any)["byRule"].([]any) {
		group := g.(map[string]any)
		if group["ruleId"] == ruleID {
			return group
		}
	}
	t.Fatalf("rule %s missing from rule view", ruleID)
	return nil
}

func toStrings(v any) []string {
	raw := v.([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		out = append(out, item.(string))
	}
	sort.Strings(out)
	return out
}

func jsonNumber(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

var _ = gosec.Error{}

// A finding must keep its key whether the scan covered one package or the
// whole module, even though the reported file path differs.
func TestKeysAreStableAcrossScanScopes(t *testing.T) {
	root := makeRoot(t, map[string]string{
		"go.mod":   "module fixture\n\ngo 1.26\n",
		"pkg/a.go": "package pkg\n\nimport \"crypto/md5\"\n\nfunc Many() {\n\t_ = md5.New()\n}\n",
	})
	file := filepath.Join(root, "pkg/a.go")

	keysFor := func(roots []string) string {
		b, out := newBuilder(t, review.FormatJSON, roots...)
		data := writeAndFinalize(t, b, out, []*issue.Issue{
			mkIssue(file, "6", "6", "G401", issue.Medium, "weak primitive"),
		}, review.Summary{})
		doc := decodeReport(t, data)
		layer := doc["views"].(map[string]any)["bySeverity"].([]any)[0].(map[string]any)
		return layer["findings"].([]any)[0].(map[string]any)["key"].(string)
	}

	wholeModule := keysFor([]string{root})
	onePackage := keysFor([]string{filepath.Join(root, "pkg")})
	if wholeModule != onePackage {
		t.Fatalf("key depends on scan scope: module scan %q, package scan %q", wholeModule, onePackage)
	}
}
