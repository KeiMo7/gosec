// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package customrules

import (
	"sync"
	"sync/atomic"
)

// RuleStats holds the runtime counters of one declarative rule. Counters are
// safe for concurrent use because package walks run in parallel workers, each
// with its own rule instance that reports back to the shared registry.
type RuleStats struct {
	// AnchorMiss counts anchor evaluations that referenced a package,
	// function or receiver type absent from the scanned code. Such anchors
	// simply never match; they never interrupt the scan.
	AnchorMiss int64
	// RegexTimeouts counts regular expression evaluations that exceeded the
	// time budget. A timed out rule is skipped for the rest of the run.
	RegexTimeouts int64
	// Unclassified counts findings produced without a CWE mapping.
	Unclassified int64
}

// Snapshot is an immutable copy of RuleStats used for reporting and tests.
type Snapshot struct {
	RuleID        string
	AnchorMiss    int64
	RegexTimeouts int64
	Unclassified  int64
}

// registry collects runtime counters keyed by rule id. It is process-global so
// that CLI runs can surface the counters after every package worker finishes.
var (
	registryMu sync.RWMutex
	registry   = map[string]*RuleStats{}
)

// registerStats returns the stats entry for a rule id, creating it on first
// use. Entries are never reset implicitly: package walks rebuild rule
// instances per package, so a reset here would erase counters from earlier
// packages. Tests reset explicitly through ResetStats.
func registerStats(ruleID string) *RuleStats {
	registryMu.Lock()
	defer registryMu.Unlock()
	stats, ok := registry[ruleID]
	if !ok {
		stats = &RuleStats{}
		registry[ruleID] = stats
	}
	return stats
}

func statsFor(ruleID string) *RuleStats {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[ruleID]
}

// StatsSnapshot returns the counters of every registered rule, ordered by id.
func StatsSnapshot() []Snapshot {
	registryMu.RLock()
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	registryMu.RUnlock()

	snapshots := make([]Snapshot, 0, len(ids))
	for _, id := range ids {
		stats := statsFor(id)
		if stats == nil {
			continue
		}
		snapshots = append(snapshots, Snapshot{
			RuleID:        id,
			AnchorMiss:    atomic.LoadInt64(&stats.AnchorMiss),
			RegexTimeouts: atomic.LoadInt64(&stats.RegexTimeouts),
			Unclassified:  atomic.LoadInt64(&stats.Unclassified),
		})
	}
	return snapshots
}

// ResetStats clears all runtime counters. It is mainly used by tests to get
// deterministic assertions.
func ResetStats() {
	registryMu.Lock()
	registry = map[string]*RuleStats{}
	registryMu.Unlock()
}
