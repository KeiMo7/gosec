package gosec_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/rules"
)

type collectingSink struct {
	mu     sync.Mutex
	issues []*issue.Issue
}

func (s *collectingSink) WriteIssue(i *issue.Issue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issues = append(s.issues, i)
	return nil
}

// writeModule writes a multi-package fixture and returns its root.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

// The streaming sink has to receive the same findings the retained path would
// report, and Report must not keep a second copy.
func TestIssueSinkReceivesAllFindings(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod": "module fixture\n\ngo 1.26\n",
		"a/a.go": "package a\n\nimport \"crypto/md5\"\n\nfunc F() { _ = md5.New() }\n",
		"b/b.go": "package b\n\nimport \"crypto/md5\"\n\nfunc G() { _ = md5.New() }\n",
	})
	logger := log.New(os.Stderr, "", 0)

	retained := gosec.NewAnalyzer(nil, false, false, false, 2, logger)
	retained.LoadRules(rules.Generate(false).RulesInfo())
	if err := retained.Process(nil, filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Fatalf("Process: %v", err)
	}
	baseline, _, _ := retained.Report()

	sink := &collectingSink{}
	streaming := gosec.NewAnalyzer(nil, false, false, false, 2, logger)
	streaming.LoadRules(rules.Generate(false).RulesInfo())
	streaming.SetIssueSink(sink)
	if err := streaming.Process(nil, filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Fatalf("Process: %v", err)
	}
	remaining, _, _ := streaming.Report()
	if len(remaining) != 0 {
		t.Fatalf("streaming mode retained %d issues in Report()", len(remaining))
	}

	describe := func(issues []*issue.Issue) []string {
		out := make([]string, 0, len(issues))
		for _, i := range issues {
			out = append(out, fmt.Sprintf("%s:%s:%s", i.RuleID, filepath.Base(i.File), i.Line))
		}
		sort.Strings(out)
		return out
	}
	want := describe(baseline)
	got := describe(sink.issues)
	if len(want) != len(got) {
		t.Fatalf("sink got %d findings, retained path got %d\n%v\n%v", len(got), len(want), got, want)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("finding %d: sink %q, retained %q", i, got[i], want[i])
		}
	}
	if len(got) == 0 {
		t.Fatal("fixture produced no findings")
	}
}

// A file that fails to parse has to be recorded as skipped while the rest of
// the scan continues.
func TestSkippedFilesAreRecorded(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":        "module fixture\n\ngo 1.26\n",
		"bad/broken.go": "package bad\n\nfunc broken( {\n",
		"good/good.go":  "package good\n\nimport \"crypto/md5\"\n\nfunc F() { _ = md5.New() }\n",
	})
	logger := log.New(os.Stderr, "", 0)
	sink := &collectingSink{}
	analyzer := gosec.NewAnalyzer(nil, false, false, false, 1, logger)
	analyzer.LoadRules(rules.Generate(false).RulesInfo())
	analyzer.SetIssueSink(sink)
	// Parse failures load fine as a package but carry ParseError entries.
	_ = analyzer.Process(nil, filepath.Join(root, "bad"), filepath.Join(root, "good"))

	skipped := analyzer.SkippedFiles()
	if len(skipped) == 0 {
		t.Fatal("expected the unparseable file to be recorded as skipped")
	}
	found := false
	for _, entry := range skipped {
		if filepath.Base(entry.File) == "broken.go" {
			found = true
			if len(entry.Errors) == 0 {
				t.Errorf("skipped file has no parse errors: %+v", entry)
			}
		}
	}
	if !found {
		t.Fatalf("broken.go not recorded, got %+v", skipped)
	}
	if len(sink.issues) == 0 {
		t.Error("scan should continue past the broken file and find issues in the good package")
	}
}

// Without a sink the analyzer keeps its historical behaviour and records no
// skipped files.
func TestNoSinkKeepsLegacyDetection(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod": "module fixture\n\ngo 1.26\n",
		"a/a.go": "package a\n\nimport \"crypto/md5\"\n\nfunc F() { _ = md5.New() }\n",
	})
	analyzer := gosec.NewAnalyzer(nil, false, false, false, 1, log.New(os.Stderr, "", 0))
	analyzer.LoadRules(rules.Generate(false).RulesInfo())
	if err := analyzer.Process(nil, filepath.Join(root, "a")); err != nil {
		t.Fatalf("Process: %v", err)
	}
	issues, _, _ := analyzer.Report()
	if len(issues) == 0 {
		t.Fatal("legacy path found no issues")
	}
	if len(analyzer.SkippedFiles()) != 0 {
		t.Errorf("legacy path recorded skipped files: %+v", analyzer.SkippedFiles())
	}
}
