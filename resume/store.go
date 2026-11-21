// Package resume implements durable, resumable scan state for gosec.
//
// The scan is partitioned into packages, which are the natural idempotent
// unit of analysis: every rule and SSA analyzer runs independently on one
// loaded package with no cross-package mutable state. This package stores the
// outcome of each package on disk so that an interrupted or repeated run can
// skip work that is already known to be current.
//
// Layout of a state directory:
//
//	config.json        scan configuration fingerprint (atomically written)
//	pkg/<key>.json     one record per package identity (atomically written)
//	events.log         append-only progress events (a torn tail is tolerated)
//	lock               process lock, held for the whole scan
//
// Nothing in a package key depends on wall-clock time, the process ID or an
// absolute filesystem path, so the same package always maps to the same key
// across runs and machines.
package resume

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// State of a package record.
const (
	// StateCompleted means the package was scanned successfully.
	StateCompleted = "completed"
	// StateFailed means the package could not be scanned (load or parse
	// failure). Failed packages are retried on every subsequent run; the
	// previous error message is preserved on the record for traceability.
	StateFailed = "failed"
)

// FormatVersion is the on-disk format version understood by this package.
// Any incompatible change must bump it.
const FormatVersion = 1

var (
	// ErrCorruptState is returned when the state directory contents cannot
	// be parsed or fail their integrity check.
	ErrCorruptState = errors.New("resume state is corrupt")
	// ErrConfigMismatch is returned when the scan configuration of a new run
	// does not match the configuration stored in the state directory.
	ErrConfigMismatch = errors.New("resume state was produced with a different scan configuration")
	// ErrLocked is returned when another gosec process already holds the
	// state directory lock.
	ErrLocked = errors.New("resume state directory is locked by another process")
)

// ConfigSnapshot captures every input that can change the findings of a scan.
// It is hashed into a fingerprint so that resuming with different rules,
// build tags or analysis options is rejected instead of silently reusing
// results produced under another configuration.
type ConfigSnapshot struct {
	// GosecConfig is the canonical JSON encoding of the gosec.Config map.
	GosecConfig json.RawMessage `json:"gosec_config"`
	// RuleIDs lists the enabled AST rule IDs in sorted order.
	RuleIDs []string `json:"rule_ids"`
	// AnalyzerIDs lists the enabled SSA analyzer IDs in sorted order.
	AnalyzerIDs []string `json:"analyzer_ids"`
	// Suppressed lists the externally suppressed rule/analyzer IDs.
	Suppressed []string `json:"suppressed"`
	// BuildTags are the Go build tags active for the scan.
	BuildTags []string `json:"build_tags"`
	// Tests enables scanning of test files.
	Tests bool `json:"tests"`
	// ExcludeGenerated skips generated files.
	ExcludeGenerated bool `json:"exclude_generated"`
	// TrackSuppressions records suppression metadata on issues.
	TrackSuppressions bool `json:"track_suppressions"`
}

// Digest returns a stable hex fingerprint of the snapshot.
func (c ConfigSnapshot) Digest() (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encoding config snapshot: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// configFile is the on-disk representation of config.json.
type configFile struct {
	Version  int            `json:"version"`
	Digest   string         `json:"digest"`
	Snapshot ConfigSnapshot `json:"snapshot"`
	Checksum string         `json:"checksum"`
}

// Record is the durable outcome of scanning one package.
type Record struct {
	// Version is the on-disk format version.
	Version int `json:"version"`
	// Key is the stable identity key of the package.
	Key string `json:"key"`
	// Identity is the human-readable stable identity (module path plus the
	// package directory relative to the module root). It never contains an
	// absolute path.
	Identity string `json:"identity"`
	// Fingerprint covers the package content and the module files that govern
	// its build. A package whose fingerprint changed is rescanned.
	Fingerprint string `json:"fingerprint"`
	// State is either StateCompleted or StateFailed.
	State string `json:"state"`
	// Issues holds the findings produced for a completed package.
	Issues []byte `json:"issues,omitempty"`
	// Errors holds the file-keyed parse/load errors produced for the package,
	// encoded as JSON. It is populated for both completed and failed records.
	Errors json.RawMessage `json:"errors,omitempty"`
	// Stats holds the metrics produced for the package.
	Stats Stats `json:"stats"`
	// LastError records the error that caused the most recent failure. Prior
	// failures are kept in ErrorHistory.
	LastError string `json:"last_error,omitempty"`
	// ErrorHistory traces failure messages across runs, oldest first.
	ErrorHistory []string `json:"error_history,omitempty"`
	// Checksum protects the record against truncated or hand-edited files.
	Checksum string `json:"checksum"`
}

// Stats is the per-package subset of gosec.Metrics that feeds the final
// report.
type Stats struct {
	Files int `json:"files"`
	Lines int `json:"lines"`
	Nosec int `json:"nosec"`
	Found int `json:"found"`
}

// recordFile is the JSON layout of a package record file. It mirrors Record
// but lets us verify the checksum before trusting the payload.
type recordFile struct {
	Record
}

// packageKey derives the stable key for an identity string. The identity is
// "module/path:relative/dir" (or a GOPATH-relative equivalent), so the key
// contains no absolute path, timestamp or process identifier.
func packageKey(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

// recordPath returns the on-disk path of the record for key.
func (s *Store) recordPath(key string) string {
	return filepath.Join(s.dir, "pkg", key+".json")
}

// atomicWriteFile writes data to dst via a temporary file in the same
// directory followed by an atomic rename. A crash at any point leaves either
// the previous complete file or the new complete file in place, never a
// partially written destination.
func atomicWriteFile(dst string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

// checksumRecord computes the integrity checksum of everything in the record
// except the checksum field itself.
func checksumRecord(r *Record) (string, error) {
	clone := *r
	clone.Checksum = ""
	raw, err := json.Marshal(&clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// writeRecord validates, checksum-protects and atomically persists a record.
func (s *Store) writeRecord(r *Record) error {
	if r.Key == "" {
		return fmt.Errorf("%w: record is missing its package key", ErrCorruptState)
	}
	checksum, err := checksumRecord(r)
	if err != nil {
		return err
	}
	r.Checksum = checksum
	data, err := json.MarshalIndent(recordFile{Record: *r}, "", "\t")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.recordPath(r.Key), data, 0o600)
}

// readRecord loads and verifies one record file.
func (s *Store) readRecord(path string) (*Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf recordFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("%w: %s cannot be parsed: %v\nRecovery: delete the file or pass -resume-reset to start a fresh scan",
			ErrCorruptState, filepath.Base(path), err)
	}
	want, err := checksumRecord(&rf.Record)
	if err != nil {
		return nil, err
	}
	if rf.Checksum == "" || rf.Checksum != want {
		return nil, fmt.Errorf("%w: %s failed its checksum; remove the file or use -resume-reset to start a fresh scan",
			ErrCorruptState, filepath.Base(path))
	}
	if rf.Version != FormatVersion {
		return nil, fmt.Errorf("%w: %s uses unsupported format version %d (supported: %d); use -resume-reset to start a fresh scan",
			ErrCorruptState, filepath.Base(path), rf.Version, FormatVersion)
	}
	return &rf.Record, nil
}

// loadRecords reads every package record in the state directory.
func (s *Store) loadRecords() error {
	dir := filepath.Join(s.dir, "pkg")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		rec, err := s.readRecord(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		s.records[rec.Key] = rec
	}
	return nil
}
