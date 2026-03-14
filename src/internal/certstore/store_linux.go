//go:build linux

// Package certstore provides system trust store operations on Linux.
// Root CA certificates are installed into the distro-specific trust anchor
// directory and activated via the appropriate update command.
package certstore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// certFileName is the fixed filename used when installing into the system trust store.
const certFileName = "stepcaagent-root.crt"

// linuxTrustConfig holds the distro-specific paths and commands.
type linuxTrustConfig struct {
	CertDir   string
	UpdateCmd string
	UpdateArg string // optional argument (e.g., "extract-compat" for Arch trust)
}

// detectTrustConfig probes the filesystem to determine the correct
// trust anchor directory and update command for this Linux distribution.
func detectTrustConfig() (*linuxTrustConfig, error) {
	candidates := []linuxTrustConfig{
		// Debian / Ubuntu / Alpine
		{CertDir: "/usr/local/share/ca-certificates", UpdateCmd: "update-ca-certificates"},
		// RHEL / Fedora / CentOS
		{CertDir: "/etc/pki/ca-trust/source/anchors", UpdateCmd: "update-ca-trust"},
		// Arch Linux
		{CertDir: "/etc/ca-certificates/trust-source/anchors", UpdateCmd: "trust", UpdateArg: "extract-compat"},
	}

	for _, c := range candidates {
		if _, err := os.Stat(c.CertDir); err != nil {
			continue
		}
		if _, err := exec.LookPath(c.UpdateCmd); err != nil {
			continue
		}
		return &c, nil
	}
	return nil, fmt.Errorf("unable to detect Linux trust store configuration")
}

// InstallRootToStore installs a root CA certificate into the system trust store.
func InstallRootToStore(rootPEM []byte, friendlyName string) error {
	log := logging.Logger()

	tc, err := detectTrustConfig()
	if err != nil {
		return fmt.Errorf("install root to system trust store: %w", err)
	}

	destPath := filepath.Join(tc.CertDir, certFileName)
	log.Info("installing root CA into system trust store",
		"path", destPath,
		"updateCmd", tc.UpdateCmd)

	if err := os.WriteFile(destPath, rootPEM, 0644); err != nil {
		return fmt.Errorf("write root CA to %s: %w", destPath, err)
	}

	var cmd *exec.Cmd
	if tc.UpdateArg != "" {
		cmd = exec.Command(tc.UpdateCmd, tc.UpdateArg)
	} else {
		cmd = exec.Command(tc.UpdateCmd)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s: %w (output: %s)", tc.UpdateCmd, err, string(output))
	}

	log.Info("root CA installed into system trust store",
		"path", destPath,
		"updateCmd", tc.UpdateCmd)
	return nil
}

// RemoveRootFromStore removes the root CA certificate from the system trust store.
func RemoveRootFromStore(rootPEM []byte) error {
	log := logging.Logger()

	tc, err := detectTrustConfig()
	if err != nil {
		return fmt.Errorf("remove root from system trust store: %w", err)
	}

	destPath := filepath.Join(tc.CertDir, certFileName)
	if _, statErr := os.Stat(destPath); os.IsNotExist(statErr) {
		log.Info("root CA not found in system trust store, nothing to remove", "path", destPath)
		return nil
	}

	if err := os.Remove(destPath); err != nil {
		return fmt.Errorf("remove root CA from %s: %w", destPath, err)
	}

	var cmd *exec.Cmd
	if tc.UpdateArg != "" {
		cmd = exec.Command(tc.UpdateCmd, tc.UpdateArg)
	} else {
		cmd = exec.Command(tc.UpdateCmd)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s: %w (output: %s)", tc.UpdateCmd, err, string(output))
	}

	log.Info("root CA removed from system trust store",
		"path", destPath,
		"updateCmd", tc.UpdateCmd)
	return nil
}

// InstallRootToStoreScoped installs a root CA into the system trust store.
// On Linux the scope parameter is ignored — the system-wide trust store is always used.
func InstallRootToStoreScoped(rootPEM []byte, friendlyName string, scope StoreScope) error {
	return InstallRootToStore(rootPEM, friendlyName)
}

// --- Leaf and intermediate store operations are no-ops on Linux ---
// Applications reference cert/key files directly on Linux.

// InstallCertToStore is a no-op on Linux.
func InstallCertToStore(certPEM []byte, storeName, friendlyName string) error {
	return nil
}

// IsCertInStore always returns false on Linux (no personal cert store).
func IsCertInStore(certPEM []byte, storeName string) (bool, error) {
	return false, nil
}

// RemoveCertFromStore is a no-op on Linux.
func RemoveCertFromStore(certPEM []byte, storeName string) error {
	return nil
}

// InstallIntermediateToStore is a no-op on Linux.
func InstallIntermediateToStore(chainPEM []byte, friendlyName string) error {
	return nil
}

// InstallIntermediateToStoreScoped is a no-op on Linux.
func InstallIntermediateToStoreScoped(chainPEM []byte, friendlyName string, scope StoreScope) error {
	return nil
}

// InstallLeafToStore is a no-op on Linux.
func InstallLeafToStore(certPEM []byte, friendlyName string) error {
	return nil
}

// InstallLeafToStoreScoped is a no-op on Linux.
func InstallLeafToStoreScoped(certPEM []byte, friendlyName string, scope StoreScope) error {
	return nil
}

// RemoveIntermediateFromStore is a no-op on Linux.
func RemoveIntermediateFromStore(chainPEM []byte) error {
	return nil
}

// RemoveLeafFromStore is a no-op on Linux.
func RemoveLeafFromStore(certPEM []byte) error {
	return nil
}

