// Package permissions provides platform-specific file permission enforcement.
// On Windows it uses NTFS ACLs; on macOS/Linux it uses POSIX file modes.
//
// The primary operations are:
//   - VerifyRestrictive: check that a file has appropriately restrictive permissions
//   - EnforceRestrictive: apply restrictive permissions to a file
package permissions

import (
	"fmt"
	"os"
	"runtime"
)

// RestrictiveFileMode is the POSIX mode used on macOS/Linux (owner-only read/write).
const RestrictiveFileMode os.FileMode = 0600

// RestrictiveDirMode is the POSIX mode for directories (owner-only rwx).
const RestrictiveDirMode os.FileMode = 0700

// VerifyRestrictive checks that the file at path has restrictive permissions.
// On Unix: verifies mode is 0600 or stricter (no group/other bits).
// On Windows: verifies the ACL restricts access to the service account and Administrators.
// Returns nil if permissions are acceptable, or an error describing the issue.
func VerifyRestrictive(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	return verifyRestrictivePlatform(path, info)
}

// EnforceRestrictive applies restrictive permissions to the file at path.
// On Unix: sets mode 0600.
// On Windows: sets NTFS ACL restricting to current user and Administrators.
func EnforceRestrictive(path string) error {
	return enforceRestrictivePlatform(path)
}

// EnforceRestrictiveDir applies restrictive permissions to a directory.
// On Unix: sets mode 0700.
// On Windows: sets NTFS ACL restricting to current user and Administrators.
func EnforceRestrictiveDir(path string) error {
	return enforceRestrictiveDirPlatform(path)
}

// PlatformDescription returns a human-readable description of the permission
// model used on the current platform.
func PlatformDescription() string {
	switch runtime.GOOS {
	case "windows":
		return "NTFS ACL (service account + Administrators only)"
	case "darwin":
		return "POSIX 0600, owned by service user (root or launchd user)"
	default:
		return "POSIX 0600, owned by service user (root or systemd user)"
	}
}

