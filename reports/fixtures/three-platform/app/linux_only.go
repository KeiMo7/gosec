//go:build linux

package app

import "os"

// LinuxOnly wraps a Linux specific syscall surface.
func LinuxOnly() {
	_ = os.Chmod("linux-config", 0777)
}
