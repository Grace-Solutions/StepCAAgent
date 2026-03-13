//go:build windows

package permissions

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// verifyRestrictivePlatform checks Windows NTFS ACLs using icacls.
// It verifies that the file does not grant access to Users, Everyone, or
// Authenticated Users groups.
func verifyRestrictivePlatform(path string, info os.FileInfo) error {
	_ = info // not used on Windows; we check ACLs directly

	out, err := exec.Command("icacls", path).Output()
	if err != nil {
		return fmt.Errorf("icacls %s: %w", path, err)
	}

	output := strings.ToLower(string(out))

	// Check for overly permissive entries.
	disallowed := []string{
		"everyone",
		"builtin\\users",
		"authenticated users",
	}
	for _, d := range disallowed {
		if strings.Contains(output, d) {
			return fmt.Errorf("file %s grants access to %q; should be restricted to service account and Administrators", path, d)
		}
	}
	return nil
}

// enforceRestrictivePlatform uses icacls to restrict a file to the current
// user and the Administrators group. It:
//  1. Disables ACL inheritance
//  2. Removes all inherited ACEs
//  3. Grants full control to Administrators and the current user
func enforceRestrictivePlatform(path string) error {
	return applyRestrictiveACL(path)
}

// enforceRestrictiveDirPlatform applies the same restrictive ACL to a directory.
func enforceRestrictiveDirPlatform(path string) error {
	return applyRestrictiveACL(path)
}

func applyRestrictiveACL(path string) error {
	// Disable inheritance and remove inherited ACEs.
	if out, err := exec.Command("icacls", path, "/inheritance:r").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls inheritance:r on %s: %s: %w", path, string(out), err)
	}

	// Grant full control to Administrators.
	if out, err := exec.Command("icacls", path, "/grant:r", "Administrators:(F)").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls grant Administrators on %s: %s: %w", path, string(out), err)
	}

	// Grant full control to SYSTEM.
	if out, err := exec.Command("icacls", path, "/grant:r", "SYSTEM:(F)").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls grant SYSTEM on %s: %s: %w", path, string(out), err)
	}

	// Grant full control to the current user.
	user := os.Getenv("USERNAME")
	if user != "" {
		if out, err := exec.Command("icacls", path, "/grant:r", user+":(F)").CombinedOutput(); err != nil {
			return fmt.Errorf("icacls grant %s on %s: %s: %w", user, path, string(out), err)
		}
	}

	return nil
}

