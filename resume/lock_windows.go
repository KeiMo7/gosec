//go:build windows

package resume

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// acquireLock takes an exclusive lock for the whole scan by denying sharing
// on the lock file. A second process fails with ErrLocked.
func acquireLock(path string) (*os.File, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, // no sharing => exclusive
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, syscall.ERROR_SHARING_VIOLATION) {
			return nil, fmt.Errorf("%w: another gosec process is using this state directory", ErrLocked)
		}
		return nil, fmt.Errorf("opening lock file %q: %w", path, err)
	}
	return os.NewFile(uintptr(handle), path), nil
}

func (s *Store) releaseLock() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}
