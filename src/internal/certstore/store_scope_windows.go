//go:build windows

package certstore

import "golang.org/x/sys/windows"

// isElevated returns true if the current process is running with
// elevated (Administrator) privileges on Windows.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

