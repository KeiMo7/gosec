package gosec

import (
	"os"
	"path/filepath"

	"github.com/securego/gosec/v2/resume"
)

// ResetResumeState clears a resume state directory so the next scan starts
// fresh under its current configuration: package records, the progress event
// log and the stored configuration fingerprint are removed, while the
// directory itself is kept. It backs the -resume-reset CLI flag and is also
// the documented recovery action after a configuration change or corrupt
// state.
func ResetResumeState(stateDir string) error {
	if stateDir == "" {
		return resume.ErrCorruptState
	}
	for _, target := range []string{
		filepath.Join(stateDir, "pkg"),
		filepath.Join(stateDir, "events.log"),
		filepath.Join(stateDir, "config.json"),
	} {
		if err := os.RemoveAll(target); err != nil {
			return err
		}
	}
	return os.MkdirAll(filepath.Join(stateDir, "pkg"), 0o700)
}
