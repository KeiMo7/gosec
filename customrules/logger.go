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
	"log"
	"os"
	"sync"
	"sync/atomic"
)

// logHook is the sink for runtime warnings (regex timeouts, unclassified
// findings). The CLI wires its analyzer logger here; standalone library use
// falls back to a stderr logger.
var (
	loggerMu sync.RWMutex
	logger   = log.New(os.Stderr, "[gosec] ", log.LstdFlags)
)

// SetLogger overrides the runtime warning logger. Passing nil restores the
// default stderr logger.
func SetLogger(l *log.Logger) {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	if l == nil {
		l = log.New(os.Stderr, "[gosec] ", log.LstdFlags)
	}
	logger = l
}

func logf(format string, args ...any) {
	loggerMu.RLock()
	l := logger
	loggerMu.RUnlock()
	l.Printf(format, args...)
}

func (s *RuleStats) addAnchorMiss() {
	atomic.AddInt64(&s.AnchorMiss, 1)
}

func (s *RuleStats) addRegexTimeout() {
	atomic.AddInt64(&s.RegexTimeouts, 1)
}

func (s *RuleStats) addUnclassified() {
	atomic.AddInt64(&s.Unclassified, 1)
}
