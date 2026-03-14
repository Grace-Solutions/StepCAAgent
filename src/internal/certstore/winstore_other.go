//go:build !windows

// Package certstore provides certificate store stubs for non-Windows platforms.
package certstore

import "github.com/GraceSolutions/StepCAAgent/internal/logging"

// InstallCertToStore is a no-op on non-Windows platforms.
func InstallCertToStore(certPEM []byte, storeName string) error {
	log := logging.Logger()
	log.Info("Windows certificate store not available on this platform, skipping", "store", storeName)
	return nil
}

// IsCertInStore always returns false on non-Windows platforms.
func IsCertInStore(certPEM []byte, storeName string) (bool, error) {
	return false, nil
}

// InstallRootToStore is a no-op on non-Windows platforms.
func InstallRootToStore(rootPEM []byte) error {
	return nil
}

// InstallIntermediateToStore is a no-op on non-Windows platforms.
func InstallIntermediateToStore(chainPEM []byte) error {
	return nil
}

// InstallLeafToStore is a no-op on non-Windows platforms.
func InstallLeafToStore(certPEM []byte) error {
	return nil
}

