//go:build windows

package app

import "os"

// WindowsOnly wraps a Windows specific syscall surface.
func WindowsOnly() {
	_ = os.Chmod("windows-config", 0777)
}
