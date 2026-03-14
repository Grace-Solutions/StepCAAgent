//go:build !windows

package certstore

import "os"

// isElevated returns true if the current process is running as root (UID 0)
// on Unix-like systems (Linux, macOS, BSDs).
func isElevated() bool {
	return os.Getuid() == 0
}

