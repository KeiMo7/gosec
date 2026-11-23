//go:build windows

package app

import "os"

// WindowsOnly deliberately does not compile so this platform fails to load.
func WindowsOnly() {
	_ = os.Chmod("windows-config", 0777)
	_ = undefinedWindowsThing()
}
