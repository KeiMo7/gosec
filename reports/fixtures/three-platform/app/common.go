package app

import "os"

// Common builds on every platform, so its finding applies to all targets.
func Common() {
	_ = os.Chmod("shared-config", 0777)
}
