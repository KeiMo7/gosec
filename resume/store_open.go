package resume

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Event kinds written to events.log.
const (
	EventStart     = "start"     // a run started
	EventReuse     = "reuse"     // a current record was reused, no rescan
	EventRescan    = "rescan"    // a package was scanned because content changed or it had failed
	EventCompleted = "completed" // a package scan finished successfully
	EventFailed    = "failed"    // a package scan failed and was marked skipped
	EventFinish    = "finish"    // the run finished
)

// Event is one progress line in events.log. Timestamps are kept only in the
// human-facing log; they never participate in package identity or reuse.
type Event struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Key      string    `json:"key,omitempty"`
	Identity string    `json:"identity,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// Store owns the durable state of a resumable scan for one state directory.
type Store struct {
	dir     string
	records map[string]*Record
	config  *configFile
	events  *os.File
	writer  *bufio.Writer
	lock    *os.File
}

// Open opens (creating if needed) a state directory, validates its contents,
// verifies that the given configuration matches the stored one and acquires
// the process lock. Writability is checked up front so an unwritable
// directory fails fast at startup instead of halfway through a scan.
func Open(dir string, snapshot ConfigSnapshot) (*Store, error) {
	if dir == "" {
		return nil, errors.New("resume state directory is empty")
	}
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0o700); err != nil {
		return nil, fmt.Errorf("creating resume state directory %q: %w", dir, err)
	}
	// Fail fast on read-only or otherwise unwritable state directories.
	if err := checkWritable(dir); err != nil {
		return nil, fmt.Errorf("resume state directory %q is not writable: %w", dir, err)
	}

	lock, err := acquireLock(filepath.Join(dir, "lock"))
	if err != nil {
		return nil, err
	}

	s := &Store{
		dir:     dir,
		records: make(map[string]*Record),
		lock:    lock,
	}
	if err := s.loadRecords(); err != nil {
		_ = s.releaseLock()
		return nil, err
	}
	if err := s.openConfig(snapshot); err != nil {
		_ = s.releaseLock()
		return nil, err
	}
	if err := s.openEvents(); err != nil {
		_ = s.releaseLock()
		return nil, err
	}
	return s, nil
}

// checkWritable verifies that a file can be created, synced and removed in
// the state directory.
func checkWritable(dir string) error {
	probe := filepath.Join(dir, ".write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("probe"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(probe)
}

// openConfig validates an existing config.json, or atomically writes the
// snapshot for a fresh state directory. A mismatch is reported with the
// exact remediation rather than silently restarting the scan.
func (s *Store) openConfig(snapshot ConfigSnapshot) error {
	digest, err := snapshot.Digest()
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("%w: reading config.json: %v", ErrCorruptState, err)
		}
		return s.writeConfig(snapshot, digest)
	}

	var stored configFile
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("%w: config.json cannot be parsed: %v\nRecovery: delete %q (or pass -resume-reset) to start a fresh scan",
			ErrCorruptState, err, s.dir)
	}
	want, err := checksumConfig(&stored)
	if err != nil {
		return err
	}
	if stored.Checksum == "" || stored.Checksum != want {
		return fmt.Errorf("%w: config.json failed its checksum\nRecovery: delete %q (or pass -resume-reset) to start a fresh scan",
			ErrCorruptState, s.dir)
	}
	if stored.Version != FormatVersion {
		return fmt.Errorf("%w: config.json uses unsupported format version %d (supported: %d)\nRecovery: pass -resume-reset to start a fresh scan",
			ErrCorruptState, stored.Version, FormatVersion)
	}
	if stored.Digest != digest {
		return fmt.Errorf("%w:\n  stored digest:   %s\n  current digest:  %s\nThe rules, build tags or analysis options changed since the state was written.\nRecovery: pass -resume-reset (or point -resume-dir at a new directory) to start a fresh scan",
			ErrConfigMismatch, stored.Digest, digest)
	}
	s.config = &stored
	return nil
}

// writeConfig atomically persists the configuration snapshot.
func (s *Store) writeConfig(snapshot ConfigSnapshot, digest string) error {
	cf := configFile{
		Version:  FormatVersion,
		Digest:   digest,
		Snapshot: snapshot,
	}
	checksum, err := checksumConfig(&cf)
	if err != nil {
		return err
	}
	cf.Checksum = checksum
	data, err := json.MarshalIndent(&cf, "", "\t")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(s.dir, "config.json"), data, 0o600); err != nil {
		return fmt.Errorf("writing config.json: %w", err)
	}
	s.config = &cf
	return nil
}

// openEvents opens the append-only event log, tolerating a torn final line
// left by a crash mid-write.
func (s *Store) openEvents() error {
	path := filepath.Join(s.dir, "events.log")
	if err := repairTornTail(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening events.log: %w", err)
	}
	s.events = f
	s.writer = bufio.NewWriter(f)
	return nil
}

// repairTornTail truncates a final line that is not terminated by a newline,
// which is the only damage an unclean kill can leave in an append-only log of
// newline-delimited JSON.
func repairTornTail(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 || data[len(data)-1] == '\n' {
		return nil
	}
	lastNL := -1
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' {
			lastNL = i
			break
		}
	}
	return os.Truncate(path, int64(lastNL+1))
}

// Log appends a progress event and flushes it immediately so progress is
// observable and durable after every package boundary.
func (s *Store) Log(kind, key, identity, detail string) error {
	ev := Event{
		Time:     time.Now().UTC(),
		Kind:     kind,
		Key:      key,
		Identity: identity,
		Detail:   detail,
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := s.writer.Write(raw); err != nil {
		return err
	}
	if err := s.writer.WriteByte('\n'); err != nil {
		return err
	}
	if err := s.writer.Flush(); err != nil {
		return err
	}
	return s.events.Sync()
}

// Close flushes the event log and releases the lock.
func (s *Store) Close() error {
	var errs []error
	if s.writer != nil {
		if err := s.writer.Flush(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.events != nil {
		if err := s.events.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.releaseLock(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
