package app

import "os"

// Common builds on every platform.
func Common() {
	_ = os.Chmod("shared-config", 0777)
}
