package resume

import (
	"encoding/json"
	"fmt"
)

// Decision tells the analyzer whether a package can be reused from the state
// directory or must be scanned again.
type Decision struct {
	Plan *Plan
	// Reuse is true when a completed record with a matching fingerprint
	// already exists.
	Reuse bool
	// Reason explains the decision for the progress log.
	Reason string
	// Existing is the stored record when one exists (including failed or
	// stale records), otherwise nil.
	Existing *Record
}

// Decide classifies a planned package against the durable state.
func (s *Store) Decide(plan *Plan) Decision {
	rec, ok := s.records[plan.Key]
	if !ok {
		return Decision{Plan: plan, Reason: "new package"}
	}
	if rec.State == StateCompleted && rec.Fingerprint == plan.Fingerprint {
		return Decision{Plan: plan, Reuse: true, Reason: "up to date", Existing: rec}
	}
	switch {
	case rec.State == StateFailed:
		return Decision{Plan: plan, Reason: "retrying previously failed package", Existing: rec}
	case rec.Fingerprint != plan.Fingerprint:
		return Decision{Plan: plan, Reason: "content changed since last scan", Existing: rec}
	default:
		return Decision{Plan: plan, Reason: "record not completed", Existing: rec}
	}
}

// Record persists the outcome of scanning one package.
func (s *Store) Record(plan *Plan, state string, issuesJSON []byte, errorsJSON json.RawMessage, stats Stats, scanErr error, previous *Record) (*Record, error) {
	rec := &Record{
		Version:     FormatVersion,
		Key:         plan.Key,
		Identity:    plan.Identity,
		Fingerprint: plan.Fingerprint,
		State:       state,
		Issues:      issuesJSON,
		Errors:      errorsJSON,
		Stats:       stats,
	}
	if scanErr != nil {
		rec.LastError = scanErr.Error()
	}
	// Carry the failure trail across runs so a retried package still points
	// at the reason of its previous failure.
	if previous != nil {
		rec.ErrorHistory = append(rec.ErrorHistory, previous.ErrorHistory...)
		if previous.LastError != "" {
			rec.ErrorHistory = append(rec.ErrorHistory, previous.LastError)
		}
	}
	if state == StateFailed && scanErr == nil {
		return nil, fmt.Errorf("internal error: failed record requires an error")
	}
	if err := s.writeRecord(rec); err != nil {
		return nil, err
	}
	s.records[rec.Key] = rec
	return rec, nil
}

// RecordNoGo persists a skipped package that has no buildable Go files, so
// repeated runs keep skipping it without invoking the loader.
func (s *Store) RecordNoGo(plan *Plan, previous *Record) (*Record, error) {
	rec := &Record{
		Version:     FormatVersion,
		Key:         plan.Key,
		Identity:    plan.Identity,
		Fingerprint: plan.Fingerprint,
		State:       StateCompleted,
		Stats:       Stats{},
	}
	if previous != nil {
		rec.ErrorHistory = append(rec.ErrorHistory, previous.ErrorHistory...)
		if previous.LastError != "" {
			rec.ErrorHistory = append(rec.ErrorHistory, previous.LastError)
		}
	}
	if err := s.writeRecord(rec); err != nil {
		return nil, err
	}
	s.records[rec.Key] = rec
	return rec, nil
}

// Lookup returns the stored record for a key, if any.
func (s *Store) Lookup(key string) (*Record, bool) {
	rec, ok := s.records[key]
	return rec, ok
}

// Counts summarises the durable state for progress reporting.
type Counts struct {
	Completed int
	Failed    int
	Total     int
}

// SnapshotCounts counts records by state.
func (s *Store) SnapshotCounts() Counts {
	c := Counts{Total: len(s.records)}
	for _, rec := range s.records {
		switch rec.State {
		case StateCompleted:
			c.Completed++
		case StateFailed:
			c.Failed++
		}
	}
	return c
}
