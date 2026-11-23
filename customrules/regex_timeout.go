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
	"context"
	"regexp"
	"time"
)

// defaultRegexTimeout bounds a single user supplied regular expression
// evaluation so that pathological inputs cannot stall a scan. Go's regexp
// engine is linear time and not interruptible, so the evaluation keeps running
// in its goroutine until it finishes; the caller gets the timeout immediately
// and the rule is marked skipped. The goroutine only consumes CPU, it never
// touches the network or the filesystem.
const defaultRegexTimeout = 100 * time.Millisecond

// regexTimeout is overridable in tests to keep the timeout test fast.
var regexTimeout = defaultRegexTimeout

// evalHook, when non-nil, is invoked inside the evaluation goroutine before
// the regexp runs. It exists to exercise the timeout guard deterministically in
// tests without depending on wall-clock behaviour of the linear-time RE2
// engine. Production code never sets it.
var evalHook func(input string)

// SetRegexTimeoutForTest overrides the per-evaluation time budget. A zero
// duration restores the default. It is intended for tests only.
func SetRegexTimeoutForTest(timeout time.Duration) {
	if timeout == 0 {
		regexTimeout = defaultRegexTimeout
		return
	}
	regexTimeout = timeout
}

// SetEvalHookForTest installs the evaluation hook. It is intended for tests
// only.
func SetEvalHookForTest(hook func(input string)) {
	evalHook = hook
}

// matchRegexWithTimeout reports whether re matches input. A timeout returns
// (false, true). The done channel is buffered so the worker goroutine never
// blocks on a caller that already gave up.
func matchRegexWithTimeout(ctx context.Context, re *regexp.Regexp, input string) (matched bool, timedOut bool) {
	done := make(chan bool, 1)
	go func() {
		if evalHook != nil {
			evalHook(input)
		}
		done <- re.MatchString(input)
	}()
	timer := time.NewTimer(regexTimeout)
	defer timer.Stop()
	select {
	case result := <-done:
		return result, false
	case <-timer.C:
		return false, true
	case <-ctx.Done():
		return false, true
	}
}
