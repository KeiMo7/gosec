package analyzers_test

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/analyzers"
)

// writeModule creates an on-disk Go module (with go.mod) and runs gosec
// through the real packages.Load path. This mirrors production exactly, unlike
// the in-memory TestPackage harness whose SSA construction of stdlib bodies
// differs and under-approximates the flow engine.
func writeModule(t *testing.T, dir, code string) string {
	t.Helper()
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module m\n\ngo 1.25\n"), 0o600))
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(code), 0o600))
	return dir
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestFlowEngineOnRealModule drives representative taint flows through an
// actual module build so the cross-goroutine and helper-function coverage is
// validated on the same SSA path used by the gosec CLI.
func TestFlowEngineOnRealModule(t *testing.T) {
	cases := []struct {
		name     string
		rule     string
		code     string
		minFinds int
	}{
		{
			name: "G701 channel worker",
			rule: "G701",
			code: `package main
import (
	"database/sql"
	"net/http"
)
func worker(ch chan string, db *sql.DB) { db.Exec("X " + <-ch) }
func handler(db *sql.DB, r *http.Request) {
	ch := make(chan string)
	go worker(ch, db)
	ch <- r.FormValue("id")
}
func main() {}
`,
			minFinds: 1,
		},
		{
			name: "G701 numeric round trip",
			rule: "G701",
			code: `package main
import (
	"database/sql"
	"net/http"
	"strconv"
)
func handler(db *sql.DB, r *http.Request) {
	n, err := strconv.Atoi(r.FormValue("id"))
	if err == nil {
		db.Query("Q " + strconv.Itoa(n))
	}
}
func main() {}
`,
			minFinds: 1,
		},
		{
			name: "G702 variadic exec argument",
			rule: "G702",
			code: `package main
import (
	"net/http"
	"os/exec"
)
func handler(r *http.Request) {
	exec.Command("cat", r.URL.Query().Get("file")).Run()
}
func main() {}
`,
			minFinds: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "mod")
			requireNoErr(t, os.MkdirAll(dir, 0o755))
			writeModule(t, dir, tc.code)

			an := gosec.NewAnalyzer(gosec.NewConfig(), false, false, false, 1, log.New(io.Discard, "", 0))
			an.LoadAnalyzers(analyzers.Generate(false,
				analyzers.NewAnalyzerFilter(false, tc.rule)).AnalyzersInfo())
			if err := an.Process(nil, dir); err != nil {
				t.Fatalf("process: %v", err)
			}
			issues, _, _ := an.Report()
			if len(issues) < tc.minFinds {
				t.Fatalf("rule %s: want >= %d findings, got %d", tc.rule, tc.minFinds, len(issues))
			}
		})
	}
}
