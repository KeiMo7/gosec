package resume

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSnapshot() ConfigSnapshot {
	return ConfigSnapshot{
		GosecConfig:       json.RawMessage(`{"global":{}}`),
		RuleIDs:           []string{"G101", "G401"},
		AnalyzerIDs:       []string{"G601"},
		Suppressed:        []string{"G401"},
		BuildTags:         []string{"integration"},
		Tests:             false,
		ExcludeGenerated:  true,
		TrackSuppressions: false,
	}
}

func writeModule(t *testing.T, root, module string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module "+module+"\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenCreatesAndReusesState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")

	store, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "config.json")); err != nil {
		t.Fatalf("config.json not written: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store2, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatalf("second open with identical config: %v", err)
	}
	if err := store2.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsConfigMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")

	store, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	changed := testSnapshot()
	changed.RuleIDs = []string{"G101"}
	_, err = Open(state, changed)
	if !errors.Is(err, ErrConfigMismatch) {
		t.Fatalf("expected ErrConfigMismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "-resume-reset") {
		t.Fatalf("error must explain recovery: %v", err)
	}
}

func TestOpenRejectsUnwritableDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission checks")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "ro")
	if err := os.MkdirAll(state, 0o500); err != nil {
		t.Fatal(err)
	}
	_, err := Open(state, testSnapshot())
	if err == nil {
		t.Fatal("expected unwritable directory to be rejected at startup")
	}
	if !strings.Contains(err.Error(), "not writable") && !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected writability error, got %v", err)
	}
}

func TestLockExcludesSecondProcess(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	first, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := Open(state, testSnapshot())
	if !errors.Is(err, ErrLocked) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestCorruptRecordAndConfigAreRejected(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{Key: "abc", Identity: "example.com/mod:pkg", Fingerprint: "fp"}
	if _, err := store.Record(plan, StateCompleted, []byte("[]"), nil, Stats{Files: 1}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Hand-edit a package record.
	recPath := filepath.Join(state, "pkg", "abc.json")
	raw, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"fp"`, `"changed"`, 1)
	if err := os.WriteFile(recPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(state, testSnapshot()); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("expected ErrCorruptState for tampered record, got %v", err)
	}

	// Restore the record, then corrupt config.json.
	if err := os.WriteFile(recPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(state, "config.json")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(cfg, []byte("garbage")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(state, testSnapshot()); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("expected ErrCorruptState for corrupt config, got %v", err)
	}
}

func TestTornEventLogTailIsRepaired(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Log(EventStart, "", "", "first"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(state, "events.log")
	good, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash mid-write: append a partial line with no newline.
	if err := os.WriteFile(logPath, append(good, []byte(`{"time":"2026-`)...), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatalf("torn tail should be repaired, got %v", err)
	}
	if err := reopened.Log(EventFinish, "", "", "second"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 valid events after repair, got %d: %q", len(lines), data)
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("event line is not valid JSON: %q", line)
		}
	}
}

func TestAtomicWriteNeverLeavesPartialDestination(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	plan := &Plan{Key: "k1", Identity: "example.com/m:p", Fingerprint: "fp1"}
	if _, err := store.Record(plan, StateCompleted, []byte("[]"), nil, Stats{Files: 2}, nil, nil); err != nil {
		t.Fatal(err)
	}
	path := store.recordPath("k1")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// A failed atomic write (bad directory) must not touch the destination.
	if err := atomicWriteFile(filepath.Join(state, "does-not-exist", "x.json"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected write into missing directory to fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("destination changed despite a failed atomic write")
	}
	// No temp files left behind in pkg.
	entries, err := os.ReadDir(filepath.Join(state, "pkg"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temporary file not cleaned up: %s", e.Name())
		}
	}
}

func TestCrashDuringWriteKeepsPreviousCompleteState(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{Key: "crash", Identity: "example.com/m:p", Fingerprint: "v1"}
	if _, err := store.Record(plan, StateCompleted, []byte("[]"), nil, Stats{Files: 1}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(state, "pkg", "crash.json")
	good, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a kill in the middle of the next write: a temp file with
	// partial data is left behind, while the rename never happened.
	tmp, err := os.CreateTemp(filepath.Join(state, "pkg"), ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write([]byte(`{"version":`)); err != nil { // truncated JSON
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening must recover the complete prior record and ignore the
	// orphaned temp file rather than treating the directory as corrupt.
	reopened, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatalf("reopen after crashed write: %v", err)
	}
	rec, ok := reopened.Lookup("crash")
	if !ok {
		t.Fatal("previous complete record must survive a crashed write")
	}
	if rec.Fingerprint != "v1" {
		t.Fatalf("recovered record has wrong fingerprint %q", rec.Fingerprint)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	// The destination file itself is byte-for-byte the prior complete state.
	after, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(good) {
		t.Fatal("a crashed write must never partially overwrite the destination")
	}
}

func TestFailedRecordIsRetriedAndKeepsHistory(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store, err := Open(state, testSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{Key: "k", Identity: "example.com/m:p", Fingerprint: "fp"}

	first := errors.New("missing dependency")
	rec, err := store.Record(plan, StateFailed, nil, nil, Stats{}, first, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateFailed || rec.LastError != "missing dependency" {
		t.Fatalf("unexpected failed record: %+v", rec)
	}

	// Same content, failed state => decision must demand a rescan.
	decision := store.Decide(plan)
	if decision.Reuse {
		t.Fatal("failed package must not be reused")
	}
	if !strings.Contains(decision.Reason, "failed") {
		t.Fatalf("reason should mention failure, got %q", decision.Reason)
	}

	// A successful retry clears the failure state but preserves history.
	ok, err := store.Record(plan, StateCompleted, []byte("[]"), nil, Stats{Files: 1}, nil, rec)
	if err != nil {
		t.Fatal(err)
	}
	if ok.LastError != "" {
		t.Fatal("successful record must not carry a current error")
	}
	if len(ok.ErrorHistory) != 1 || ok.ErrorHistory[0] != "missing dependency" {
		t.Fatalf("failure history lost: %+v", ok.ErrorHistory)
	}
	if !store.Decide(plan).Reuse {
		t.Fatal("successful, current record should be reused")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
