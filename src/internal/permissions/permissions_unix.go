//go:build !windows

package permissions

import (
	"fmt"
	"os"
)

// verifyRestrictivePlatform checks POSIX permissions.
// The file must not have any group or other bits set.
func verifyRestrictivePlatform(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()

	// Check that no group or other permissions are set.
	groupOther := mode & 0077
	if groupOther != 0 {
		return fmt.Errorf("file %s has mode %04o; group/other bits are set (want 0600 or stricter)", path, mode)
	}
	return nil
}

// enforceRestrictivePlatform sets POSIX file mode to 0600.
func enforceRestrictivePlatform(path string) error {
	if err := os.Chmod(path, RestrictiveFileMode); err != nil {
		return fmt.Errorf("chmod %s to %04o: %w", path, RestrictiveFileMode, err)
	}
	return nil
}

// enforceRestrictiveDirPlatform sets POSIX dir mode to 0700.
func enforceRestrictiveDirPlatform(path string) error {
	if err := os.Chmod(path, RestrictiveDirMode); err != nil {
		return fmt.Errorf("chmod %s to %04o: %w", path, RestrictiveDirMode, err)
	}
	return nil
}

