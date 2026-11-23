//go:build linux

package app

import "os"

// LinuxOnly is healthy and must still be analyzed.
func LinuxOnly() {
	_ = os.Chmod("linux-config", 0777)
}
