package gosec_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/resume"
	"github.com/securego/gosec/v2/rules"
)

// resumeFixture builds a small multi-package module containing a real
// hardcoded-credential finding (G101), so reuse decisions can be asserted on
// actual issues rather than empty scans.
func resumeFixture(root string, pkgs map[string]string) {
	Expect(os.MkdirAll(root, 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/resume\n\ngo 1.22\n"), 0o600)).To(Succeed())
	for rel, content := range pkgs {
		full := filepath.Join(root, rel)
		Expect(os.MkdirAll(filepath.Dir(full), 0o755)).To(Succeed())
		Expect(os.WriteFile(full, []byte(content), 0o600)).To(Succeed())
	}
}

const weakPkg = `package weak

var awsAccessKeyID = "AKIAIOSFODNN7EXAMPLE"

func Cred() string { return awsAccessKeyID }
`

const cleanPkg = `package clean

func Add(a, b int) int { return a + b }
`

func newResumeAnalyzer() *gosec.Analyzer {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	a := gosec.NewAnalyzer(nil, false, false, false, 2, logger)
	a.LoadRules(rules.Generate(false).RulesInfo())
	return a
}

// canonicalReport renders the analyzer outcome the same way the JSON report
// does, so two runs can be compared byte for byte.
func canonicalReport(analyzer *gosec.Analyzer) []byte {
	issues, metrics, errs := analyzer.Report()
	// The CLI sorts issues before reporting; apply the same deterministic
	// ordering here.
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Severity != issues[j].Severity {
			return issues[i].Severity > issues[j].Severity
		}
		return issues[i].File < issues[j].File
	})
	raw, err := json.MarshalIndent(struct {
		Issues []*issue.Issue           `json:"issues"`
		Stats  *gosec.Metrics           `json:"stats"`
		Errors map[string][]gosec.Error `json:"errors"`
	}{Issues: issues, Stats: metrics, Errors: errs}, "", "\t")
	Expect(err).ShouldNot(HaveOccurred())
	return raw
}

var _ = Describe("Resumable analyzer", func() {
	var (
		moduleRoot string
		stateDir   string
		pkgDirs    []string
	)

	BeforeEach(func() {
		moduleRoot = filepath.Join(GinkgoT().TempDir(), "repo")
		stateDir = filepath.Join(GinkgoT().TempDir(), "state")
		resumeFixture(moduleRoot, map[string]string{
			filepath.Join("pkgweak", "weak.go"):   weakPkg,
			filepath.Join("pkgclean", "clean.go"): cleanPkg,
			filepath.Join("pkgother", "other.go"): `package other

func Mul(a, b int) int { return a * b }
`,
		})
		pkgDirs = []string{
			filepath.Join(moduleRoot, "pkgweak"),
			filepath.Join(moduleRoot, "pkgclean"),
			filepath.Join(moduleRoot, "pkgother"),
		}
	})

	It("produces output byte-identical to a one-shot scan", func() {
		oneShot := newResumeAnalyzer()
		Expect(oneShot.Process(nil, pkgDirs...)).To(Succeed())
		want := canonicalReport(oneShot)
		Expect(want).To(ContainSubstring("G101"))

		resumable := newResumeAnalyzer()
		report, err := resumable.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report.Total).To(Equal(3))
		Expect(report.Scanned).To(Equal(3))
		Expect(report.Reused).To(BeZero())
		got := canonicalReport(resumable)
		Expect(got).To(Equal(want))
	})

	It("reuses every package on a repeated run without rescanning", func() {
		first := newResumeAnalyzer()
		report, err := first.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report.Completed).To(Equal(3))

		second := newResumeAnalyzer()
		report2, err := second.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report2.Reused).To(Equal(3))
		Expect(report2.Scanned).To(BeZero())
		Expect(canonicalReport(second)).To(Equal(canonicalReport(first)))

		// Every package record exists and is well formed.
		entries, err := os.ReadDir(filepath.Join(stateDir, "pkg"))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(entries).To(HaveLen(3))
	})

	It("resumes after an interruption without losing completed work", func() {
		// First run: scan only a subset of the packages, simulating a killed
		// process mid-batch.
		partial := newResumeAnalyzer()
		report, err := partial.ProcessResumable(context.Background(), nil, stateDir, pkgDirs[:1]...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report.Completed).To(Equal(1))

		// The interrupted state is already durable and readable.
		entries, err := os.ReadDir(filepath.Join(stateDir, "pkg"))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(entries).To(HaveLen(1))

		// Second run over the full scope reuses the finished package and
		// only scans the remaining two.
		resumed := newResumeAnalyzer()
		report2, err := resumed.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report2.Reused).To(Equal(1))
		Expect(report2.Scanned).To(Equal(2))
		Expect(report2.Completed).To(Equal(3))

		oneShot := newResumeAnalyzer()
		Expect(oneShot.Process(nil, pkgDirs...)).To(Succeed())
		Expect(canonicalReport(resumed)).To(Equal(canonicalReport(oneShot)))
	})

	It("rescans only changed packages after code changes", func() {
		first := newResumeAnalyzer()
		_, err := first.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).ShouldNot(HaveOccurred())

		// Modify one package and add a brand new one.
		Expect(os.WriteFile(filepath.Join(moduleRoot, "pkgclean", "clean.go"),
			[]byte(`package clean

func Add(a, b int) int { return a + b + 1 }
`), 0o600)).To(Succeed())
		newPkg := filepath.Join(moduleRoot, "pkgnew")
		Expect(os.MkdirAll(newPkg, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(newPkg, "new.go"),
			[]byte(`package new

func Sub(a, b int) int { return a - b }
`), 0o600)).To(Succeed())

		second := newResumeAnalyzer()
		report, err := second.ProcessResumable(context.Background(), nil, stateDir,
			append(append([]string{}, pkgDirs...), newPkg)...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report.Reused).To(Equal(2), "the two untouched packages must be reused")
		Expect(report.Scanned).To(Equal(2), "modified and newly added packages must be scanned")

		oneShot := newResumeAnalyzer()
		Expect(oneShot.Process(nil, append(append([]string{}, pkgDirs...), newPkg)...)).To(Succeed())
		Expect(canonicalReport(second)).To(Equal(canonicalReport(oneShot)))
	})

	It("deduplicates overlapping paths within one run and reuses by identity across runs", func() {
		dup := append(append([]string{}, pkgDirs...), pkgDirs[0])
		analyzer := newResumeAnalyzer()
		report, err := analyzer.ProcessResumable(context.Background(), nil, stateDir, dup...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report.Total).To(Equal(3), "the duplicated package must be planned once")
		Expect(report.Scanned).To(Equal(3))

		again := newResumeAnalyzer()
		report2, err := again.ProcessResumable(context.Background(), nil, stateDir, dup...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report2.Reused).To(Equal(3))
	})

	It("marks persistently failing packages as skipped and retries them next run", func() {
		// A directory with a syntactically invalid Go file fails loading but
		// must not stop the other packages.
		badPkg := filepath.Join(GinkgoT().TempDir(), "badpkg")
		Expect(os.MkdirAll(badPkg, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(badPkg, "broken.go"),
			[]byte("package broken\nfunc Broken( { }\n"), 0o600)).To(Succeed())

		all := append(append([]string{}, pkgDirs...), badPkg)
		first := newResumeAnalyzer()
		report, err := first.ProcessResumable(context.Background(), nil, stateDir, all...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report.Failed).To(Equal(1))
		Expect(report.Completed).To(Equal(3), "healthy packages still complete")
		_, _, errs := first.Report()
		Expect(errs).ToNot(BeEmpty())

		// The failed package carries a traceable error on disk and is
		// retried (not reused) on the next run.
		snap, err := first.ResumeConfigSnapshot(nil)
		Expect(err).ShouldNot(HaveOccurred())
		store, err := resume.Open(stateDir, snap)
		Expect(err).ShouldNot(HaveOccurred())
		failedCount := store.SnapshotCounts().Failed
		Expect(failedCount).To(Equal(1))
		Expect(store.Close()).To(Succeed())

		second := newResumeAnalyzer()
		report2, err := second.ProcessResumable(context.Background(), nil, stateDir, all...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report2.Failed).To(Equal(1))
		Expect(report2.Scanned).To(Equal(1), "only the failed package is retried")
		Expect(report2.Reused).To(Equal(3))

		// Fix the package; the next run rescans it once and then reuses it.
		Expect(os.WriteFile(filepath.Join(badPkg, "broken.go"),
			[]byte("package broken\nfunc Broken() int { return 0 }\n"), 0o600)).To(Succeed())
		third := newResumeAnalyzer()
		report3, err := third.ProcessResumable(context.Background(), nil, stateDir, all...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report3.Failed).To(BeZero())
		Expect(report3.Scanned).To(Equal(1))
	})

	It("rejects a corrupt state file with an actionable error", func() {
		analyzer := newResumeAnalyzer()
		_, err := analyzer.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).ShouldNot(HaveOccurred())

		entries, err := os.ReadDir(filepath.Join(stateDir, "pkg"))
		Expect(err).ShouldNot(HaveOccurred())
		target := filepath.Join(stateDir, "pkg", entries[0].Name())
		raw, err := os.ReadFile(target)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(os.WriteFile(target, append(raw, []byte("tampered")...), 0o600)).To(Succeed())

		again := newResumeAnalyzer()
		_, err = again.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).To(MatchError(ContainSubstring("resume state is corrupt")))
		Expect(err.Error()).To(ContainSubstring("-resume-reset"))
	})

	It("rejects reuse when the scan configuration changed", func() {
		analyzer := newResumeAnalyzer()
		_, err := analyzer.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).ShouldNot(HaveOccurred())

		different := gosec.NewAnalyzer(nil, false, false, false, 2, log.New(os.Stderr, "", 0))
		list := rules.Generate(false, rules.NewRuleFilter(true, "G101"))
		different.LoadRules(list.RulesInfo())
		_, err = different.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).To(MatchError(ContainSubstring("different scan configuration")))
	})

	It("survives a kill while a progress write is in flight", func() {
		// Seed a completed record, then append a torn (unterminated) event
		// line exactly as an unclean kill would leave it.
		analyzer := newResumeAnalyzer()
		report, err := analyzer.ProcessResumable(context.Background(), nil, stateDir, pkgDirs[:1]...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report.Completed).To(Equal(1))

		logPath := filepath.Join(stateDir, "events.log")
		raw, err := os.ReadFile(logPath)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(os.WriteFile(logPath, append(raw, []byte(`{"time":"2026-11-22T00:00:00Z","kind":"rescan"`)...), 0o600)).
			To(Succeed())

		// Reopening must repair the torn tail and recover the full prior
		// state without rescanning the finished package.
		resumed := newResumeAnalyzer()
		report2, err := resumed.ProcessResumable(context.Background(), nil, stateDir, pkgDirs...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report2.Reused).To(Equal(1))
		Expect(report2.Completed).To(Equal(3))

		oneShot := newResumeAnalyzer()
		Expect(oneShot.Process(nil, pkgDirs...)).To(Succeed())
		Expect(canonicalReport(resumed)).To(Equal(canonicalReport(oneShot)))
	})

	It("aggregates many concurrent packages correctly and reuses all of them", func() {
		bigRoot := filepath.Join(GinkgoT().TempDir(), "bigrepo")
		state := filepath.Join(GinkgoT().TempDir(), "state")
		files := map[string]string{
			"go.mod": "module example.com/big\n\ngo 1.22\n",
		}
		const pkgCount = 25
		dirs := make([]string, 0, pkgCount)
		for i := 0; i < pkgCount; i++ {
			name := fmt.Sprintf("pkg%02d", i)
			rel := filepath.Join(name, "f.go")
			files[rel] = fmt.Sprintf("package %s\n\nfunc F%d() int { return %d }\n", name, i, i)
			dirs = append(dirs, filepath.Join(bigRoot, name))
		}
		resumeFixture(bigRoot, files)

		// High worker count relative to package count.
		logger := log.New(os.Stderr, "", 0)
		analyzer := gosec.NewAnalyzer(nil, false, false, false, 8, logger)
		analyzer.LoadRules(rules.Generate(false).RulesInfo())
		report, err := analyzer.ProcessResumable(context.Background(), nil, state, dirs...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report.Total).To(Equal(pkgCount))
		Expect(report.Completed).To(Equal(pkgCount))

		oneShot := gosec.NewAnalyzer(nil, false, false, false, 8, logger)
		oneShot.LoadRules(rules.Generate(false).RulesInfo())
		Expect(oneShot.Process(nil, dirs...)).To(Succeed())
		Expect(canonicalReport(analyzer)).To(Equal(canonicalReport(oneShot)))

		// Second run reuses every package.
		again := gosec.NewAnalyzer(nil, false, false, false, 8, logger)
		again.LoadRules(rules.Generate(false).RulesInfo())
		report2, err := again.ProcessResumable(context.Background(), nil, state, dirs...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(report2.Reused).To(Equal(pkgCount))
		Expect(report2.Scanned).To(BeZero())
	})
})

// guard against unused import when test file evolves.
var _ = strings.TrimSpace
