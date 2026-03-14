//go:build darwin

// Package certstore provides system trust store operations on macOS.
// Root CA certificates are installed into the System Keychain via the
// security CLI tool.
package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// certFileName is the fixed filename used when staging the root cert for the security CLI.
const certFileName = "stepcaagent-root.crt"

// systemKeychain is the macOS System Keychain path.
const systemKeychain = "/Library/Keychains/System.keychain"

// InstallRootToStore installs a root CA certificate into the macOS System Keychain.
func InstallRootToStore(rootPEM []byte, friendlyName string) error {
	log := logging.Logger()

	block, _ := pem.Decode(rootPEM)
	if block == nil {
		return fmt.Errorf("darwin trust: no PEM block found in root certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("darwin trust: parse root certificate: %w", err)
	}

	log.Info("installing root CA into macOS System Keychain",
		"subject", cert.Subject.CommonName,
		"keychain", systemKeychain)

	// Write to a temp file for the security CLI
	tmpDir := os.TempDir()
	tmpPath := filepath.Join(tmpDir, certFileName)
	if err := os.WriteFile(tmpPath, rootPEM, 0644); err != nil {
		return fmt.Errorf("darwin trust: write temp root cert: %w", err)
	}
	defer os.Remove(tmpPath)

	// security add-trusted-cert -d -r trustRoot -k <keychain> <cert>
	cmd := exec.Command("security", "add-trusted-cert",
		"-d",              // add to admin trust settings
		"-r", "trustRoot", // result type = trust root
		"-k", systemKeychain,
		tmpPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("darwin trust: security add-trusted-cert: %w (output: %s)", err, string(output))
	}

	log.Info("root CA installed into macOS System Keychain",
		"subject", cert.Subject.CommonName,
		"keychain", systemKeychain)
	return nil
}

// RemoveRootFromStore removes the root CA certificate from the macOS System Keychain.
func RemoveRootFromStore(rootPEM []byte) error {
	log := logging.Logger()

	// Write to a temp file for the security CLI
	tmpDir := os.TempDir()
	tmpPath := filepath.Join(tmpDir, certFileName)
	if err := os.WriteFile(tmpPath, rootPEM, 0644); err != nil {
		return fmt.Errorf("darwin trust: write temp root cert for removal: %w", err)
	}
	defer os.Remove(tmpPath)

	cmd := exec.Command("security", "remove-trusted-cert", "-d", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("root CA removal from macOS Keychain may have failed (cert might not exist)",
			"error", err, "output", string(output))
		return nil // Not a hard error — cert may not have been installed
	}

	log.Info("root CA removed from macOS System Keychain")
	return nil
}

// InstallRootToStoreScoped installs a root CA into the macOS System Keychain.
// On macOS the scope parameter is ignored — the System Keychain is always used.
func InstallRootToStoreScoped(rootPEM []byte, friendlyName string, scope StoreScope) error {
	return InstallRootToStore(rootPEM, friendlyName)
}

// --- Leaf and intermediate store operations are no-ops on macOS ---
// The macOS Keychain could be used for leaf certs, but applications on
// macOS/Linux typically reference cert/key files directly.

// InstallCertToStore is a no-op on macOS.
func InstallCertToStore(certPEM []byte, storeName, friendlyName string) error {
	return nil
}

// IsCertInStore always returns false on macOS (no personal cert store equivalent used).
func IsCertInStore(certPEM []byte, storeName string) (bool, error) {
	return false, nil
}

// RemoveCertFromStore is a no-op on macOS.
func RemoveCertFromStore(certPEM []byte, storeName string) error {
	return nil
}

// InstallIntermediateToStore is a no-op on macOS.
func InstallIntermediateToStore(chainPEM []byte, friendlyName string) error {
	return nil
}

// InstallLeafToStore is a no-op on macOS.
func InstallLeafToStore(certPEM []byte, friendlyName string) error {
	return nil
}

// RemoveIntermediateFromStore is a no-op on macOS.
func RemoveIntermediateFromStore(chainPEM []byte) error {
	return nil
}

// RemoveLeafFromStore is a no-op on macOS.
func RemoveLeafFromStore(certPEM []byte) error {
	return nil
}

