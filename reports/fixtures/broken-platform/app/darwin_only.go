//go:build darwin

package app

import "os"

// DarwinOnly is healthy and must still be analyzed.
func DarwinOnly() {
	_ = os.Chmod("darwin-config", 0777)
}
