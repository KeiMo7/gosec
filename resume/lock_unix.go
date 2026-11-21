//go:build !windows

package resume

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// acquireLock takes an exclusive, non-blocking advisory lock for the whole
// scan. It fails immediately with ErrLocked when another process already
// holds it, so two gosec runs can never interleave writes in one directory.
func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file %q: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: another gosec process is using this state directory", ErrLocked)
		}
		return nil, fmt.Errorf("acquiring lock on %q: %w", path, err)
	}
	return f, nil
}

func (s *Store) releaseLock() error {
	if s.lock == nil {
		return nil
	}
	err := errors.Join(syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN), s.lock.Close())
	s.lock = nil
	return err
}
