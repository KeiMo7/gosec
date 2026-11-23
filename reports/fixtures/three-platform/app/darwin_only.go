//go:build darwin

package app

import "os"

// DarwinOnly wraps a Darwin specific syscall surface.
func DarwinOnly() {
	_ = os.Chmod("darwin-config", 0777)
}
