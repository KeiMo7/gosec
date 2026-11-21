package gosec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/resume"
)

// ResumeReport summarises one resumable run. It lets callers (and the CLI)
// show how many packages were reused and how many were rescanned.
type ResumeReport struct {
	Total     int
	Reused    int
	Scanned   int
	Failed    int
	Skipped   int
	Completed int
}

// ruleAndAnalyzerIDs returns the enabled and externally suppressed rule and
// analyzer IDs. The lists feed the configuration fingerprint, so resuming
// under a different ruleset is rejected rather than silently reusing stale
// findings.
func (gosec *Analyzer) ruleAndAnalyzerIDs() (ruleIDs, analyzerIDs, suppressed []string) {
	for id := range gosec.ruleBuilders {
		ruleIDs = append(ruleIDs, id)
		if gosec.ruleset.IsRuleSuppressed(id) {
			suppressed = append(suppressed, id)
		}
	}
	for _, def := range gosec.analyzerSet.Analyzers {
		analyzerIDs = append(analyzerIDs, def.Name)
		if gosec.analyzerSet.IsSuppressed(def.Name) {
			suppressed = append(suppressed, def.Name)
		}
	}
	slices.Sort(ruleIDs)
	slices.Sort(analyzerIDs)
	slices.Sort(suppressed)
	return ruleIDs, analyzerIDs, suppressed
}

// ResumeConfigSnapshot returns the fingerprinted description of the current
// scan configuration. It is exported so callers and tests can open an
// existing resume store with the exact digest the analyzer would use.
func (gosec *Analyzer) ResumeConfigSnapshot(buildTags []string) (resume.ConfigSnapshot, error) {
	return gosec.resumeConfigSnapshot(buildTags)
}

// resumeConfigSnapshot builds the fingerprinted description of everything that
// can affect scan findings.
func (gosec *Analyzer) resumeConfigSnapshot(buildTags []string) (resume.ConfigSnapshot, error) {
	ruleIDs, analyzerIDs, suppressed := gosec.ruleAndAnalyzerIDs()

	rawConfig, err := json.Marshal(gosec.config)
	if err != nil {
		return resume.ConfigSnapshot{}, fmt.Errorf("encoding gosec config for resume fingerprint: %w", err)
	}
	tags := append([]string(nil), buildTags...)
	slices.Sort(tags)
	return resume.ConfigSnapshot{
		GosecConfig:       rawConfig,
		RuleIDs:           ruleIDs,
		AnalyzerIDs:       analyzerIDs,
		Suppressed:        suppressed,
		BuildTags:         tags,
		Tests:             gosec.tests,
		ExcludeGenerated:  gosec.excludeGenerated,
		TrackSuppressions: gosec.trackSuppressions,
	}, nil
}

// resumeJob pairs a package that needs scanning with the durable record it
// had before the scan.
type resumeJob struct {
	plan     *resume.Plan
	previous *resume.Record
}

// resumeOutcome is the scan result for one resumeJob.
type resumeOutcome struct {
	job resumeJob
	res packageResult
}

// ProcessResumable runs the scan with durable per-package state in stateDir.
// Completed, unchanged packages are loaded from the state instead of being
// rescanned; failed packages are retried. The aggregated issues, metrics and
// errors are identical to those produced by Process on the same code and
// configuration.
func (gosec *Analyzer) ProcessResumable(ctx context.Context, buildTags []string, stateDir string, packagePaths ...string) (*ResumeReport, error) {
	snapshot, err := gosec.resumeConfigSnapshot(buildTags)
	if err != nil {
		return nil, err
	}
	store, err := resume.Open(stateDir, snapshot)
	if err != nil {
		return nil, err
	}
	defer store.Close() // #nosec G307

	planner := resume.NewPlanner(buildTags, gosec.tests)

	// Plan and de-duplicate every requested package up front. Overlapping
	// command-line paths collapse onto the same stable key, so a package is
	// never scanned twice within one run and is always reused by identity
	// across runs.
	plans := make([]*resume.Plan, 0, len(packagePaths))
	planned := make(map[string]struct{}, len(packagePaths))
	for _, pkgPath := range packagePaths {
		plan, err := planner.PlanPackage(pkgPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Match the one-shot loader: a missing directory is logged
				// and skipped without contributing an error to the report.
				gosec.logger.Printf("Skipping: %s. Path doesn't exist.", pkgPath)
				continue
			}
			// Other planning failures still surface as package errors,
			// mirroring a load failure, without blocking the remaining batch.
			gosec.AppendError(pkgPath, err)
			continue
		}
		if _, ok := planned[plan.Key]; ok {
			continue
		}
		planned[plan.Key] = struct{}{}
		plans = append(plans, plan)
	}

	if err := store.Log(resume.EventStart, "", "",
		fmt.Sprintf("planned %d unique packages", len(plans))); err != nil {
		return nil, err
	}

	report := &ResumeReport{Total: len(plans)}
	// Both channels are buffered for every possible job, so workers never
	// block on a send while the orchestrator handles a persistence error.
	jobs := make(chan resumeJob, len(plans))
	outcomes := make(chan resumeOutcome, len(plans))

	// A cancelable context lets the orchestrator stop in-flight workers when
	// persistence fails or the caller gives up, instead of leaking them.
	groupCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Decide reuse vs. rescan sequentially: only this goroutine touches the
	// store, and only packages that genuinely need scanning enter the worker
	// pool.
	queued := 0
	for _, plan := range plans {
		decision := store.Decide(plan)
		if decision.Reuse {
			if err := gosec.mergeRecord(decision.Existing); err != nil {
				return nil, err
			}
			report.Reused++
			report.Completed++
			if err := store.Log(resume.EventReuse, plan.Key, plan.Identity, decision.Reason); err != nil {
				return nil, err
			}
			continue
		}
		if plan.NoGo {
			if _, err := store.RecordNoGo(plan, decision.Existing); err != nil {
				return nil, err
			}
			report.Skipped++
			report.Completed++
			if err := store.Log(resume.EventRescan, plan.Key, plan.Identity,
				"no buildable Go files; recorded as skipped"); err != nil {
				return nil, err
			}
			continue
		}
		jobs <- resumeJob{plan: plan, previous: decision.Existing}
		queued++
		report.Scanned++
		if err := store.Log(resume.EventRescan, plan.Key, plan.Identity, decision.Reason); err != nil {
			return nil, err
		}
	}
	close(jobs)

	g := new(errgroup.Group)
	workers := max(gosec.concurrency, 1)
	g.SetLimit(workers)
	for i := 0; i < workers; i++ {
		g.Go(func() error {
			for {
				select {
				case job, ok := <-jobs:
					if !ok {
						return nil
					}
					r := gosec.processPackage(groupCtx, buildTags, job.plan.Path)
					select {
					case outcomes <- resumeOutcome{job: job, res: r}:
					case <-groupCtx.Done():
						return groupCtx.Err()
					}
				case <-groupCtx.Done():
					return groupCtx.Err()
				}
			}
		})
	}

	// Persist each outcome as soon as it lands, so an interruption never
	// loses progress on packages already analyzed. A persistence failure
	// cancels the workers; buffered outcomes for the remaining in-flight jobs
	// are simply discarded.
	var persistErr error
	for processed := 0; processed < queued; processed++ {
		select {
		case outcome := <-outcomes:
			if persistErr != nil {
				continue
			}
			if err := gosec.persistPackageResult(store, outcome.job, outcome.res, report); err != nil {
				persistErr = err
				cancel()
			}
		case <-groupCtx.Done():
			// Only reachable when the parent context is canceled, since
			// workers otherwise fill the buffered channel for every job.
			if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
				return report, err
			}
			return report, groupCtx.Err()
		}
	}
	cancel()
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return report, err
	}
	if persistErr != nil {
		return report, persistErr
	}

	sortErrors(gosec.errors)
	if err := store.Log(resume.EventFinish, "", "",
		fmt.Sprintf("reused=%d scanned=%d failed=%d skipped=%d", report.Reused, report.Scanned, report.Failed, report.Skipped)); err != nil {
		return nil, err
	}
	return report, nil
}

// persistPackageResult merges a package scan outcome into the analyzer and
// writes its durable record in the same step, so an interruption never loses
// a package that has already been fully analyzed.
//
// A package is classified as failed when the loader returns a fatal error
// or the loaded package carries parse/type errors: the one-shot Process path
// records both kinds in the analyzer's error map without aborting, and the
// resumable path mirrors that while marking the package for retry on the
// next run.
func (gosec *Analyzer) persistPackageResult(store *resume.Store, job resumeJob, r packageResult, report *ResumeReport) error {
	plan := job.plan
	failed := r.err != nil || len(r.errors) > 0

	if r.err != nil {
		gosec.AppendError(r.pkgPath, r.err)
	}
	for file, matches := range r.errors {
		gosec.errors[file] = append(gosec.errors[file], matches...)
	}
	gosec.issues = append(gosec.issues, r.issues...)
	gosec.stats.Merge(r.stats)

	issuesJSON, err := json.Marshal(r.issues)
	if err != nil {
		return err
	}
	errorsJSON, err := json.Marshal(gosec.packageErrors(r))
	if err != nil {
		return err
	}

	if failed {
		scanErr := r.err
		if scanErr == nil {
			scanErr = fmt.Errorf("package %q reported %d build/parse error(s)", plan.Identity, len(r.errors))
		}
		if _, err := store.Record(plan, resume.StateFailed, issuesJSON, errorsJSON,
			resume.Stats{
				Files: r.stats.NumFiles,
				Lines: r.stats.NumLines,
				Nosec: r.stats.NumNosec,
				Found: r.stats.NumFound,
			}, scanErr, job.previous); err != nil {
			return err
		}
		report.Failed++
		return store.Log(resume.EventFailed, plan.Key, plan.Identity, scanErr.Error())
	}

	if _, err := store.Record(plan, resume.StateCompleted, issuesJSON, errorsJSON,
		resume.Stats{
			Files: r.stats.NumFiles,
			Lines: r.stats.NumLines,
			Nosec: r.stats.NumNosec,
			Found: r.stats.NumFound,
		}, nil, job.previous); err != nil {
		return err
	}
	report.Completed++
	return store.Log(resume.EventCompleted, plan.Key, plan.Identity,
		fmt.Sprintf("issues=%d files=%d", len(r.issues), r.stats.NumFiles))
}

// packageErrors gathers every error attributed to one scanned package,
// including the fatal loader error (keyed by package path exactly as
// AppendError records it in the one-shot path).
func (gosec *Analyzer) packageErrors(r packageResult) map[string][]Error {
	combined := make(map[string][]Error, len(r.errors)+1)
	for file, matches := range r.errors {
		combined[file] = append(combined[file], matches...)
	}
	if r.err != nil {
		combined[r.pkgPath] = append(combined[r.pkgPath], *NewError(0, 0, r.err.Error()))
	}
	return combined
}

// mergeRecord replays a reusable package record into the analyzer's
// aggregated issues, metrics and errors.
func (gosec *Analyzer) mergeRecord(rec *resume.Record) error {
	if len(rec.Issues) > 0 {
		var issues []*issue.Issue
		if err := json.Unmarshal(rec.Issues, &issues); err != nil {
			return fmt.Errorf("%w: decoding cached issues for %s: %v", resume.ErrCorruptState, rec.Identity, err)
		}
		gosec.issues = append(gosec.issues, issues...)
	}
	gosec.stats.NumFiles += rec.Stats.Files
	gosec.stats.NumLines += rec.Stats.Lines
	gosec.stats.NumNosec += rec.Stats.Nosec
	gosec.stats.NumFound += rec.Stats.Found
	if len(rec.Errors) > 0 {
		var fileErrors map[string][]Error
		if err := json.Unmarshal(rec.Errors, &fileErrors); err != nil {
			return fmt.Errorf("%w: decoding cached errors for %s: %v", resume.ErrCorruptState, rec.Identity, err)
		}
		for file, matches := range fileErrors {
			gosec.errors[file] = append(gosec.errors[file], matches...)
		}
	}
	return nil
}
