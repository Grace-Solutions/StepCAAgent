//go:build !windows && !linux && !darwin

// Package certstore provides certificate store stubs for unsupported platforms.
package certstore

import "github.com/GraceSolutions/StepCAAgent/internal/logging"

// InstallCertToStore is a no-op on unsupported platforms.
func InstallCertToStore(certPEM []byte, storeName, friendlyName string) error {
	log := logging.Logger()
	log.Info("certificate store not available on this platform, skipping", "store", storeName)
	return nil
}

// IsCertInStore always returns false on unsupported platforms.
func IsCertInStore(certPEM []byte, storeName string) (bool, error) {
	return false, nil
}

// RemoveCertFromStore is a no-op on unsupported platforms.
func RemoveCertFromStore(certPEM []byte, storeName string) error {
	return nil
}

// InstallRootToStore is a no-op on unsupported platforms.
func InstallRootToStore(rootPEM []byte, friendlyName string) error {
	log := logging.Logger()
	log.Info("system trust store not available on this platform, skipping root install")
	return nil
}

// InstallRootToStoreScoped is a no-op on unsupported platforms.
func InstallRootToStoreScoped(rootPEM []byte, friendlyName string, scope StoreScope) error {
	return InstallRootToStore(rootPEM, friendlyName)
}

// InstallIntermediateToStore is a no-op on unsupported platforms.
func InstallIntermediateToStore(chainPEM []byte, friendlyName string) error {
	return nil
}

// InstallLeafToStore is a no-op on unsupported platforms.
func InstallLeafToStore(certPEM []byte, friendlyName string) error {
	return nil
}

// RemoveRootFromStore is a no-op on unsupported platforms.
func RemoveRootFromStore(rootPEM []byte) error {
	return nil
}

// RemoveIntermediateFromStore is a no-op on unsupported platforms.
func RemoveIntermediateFromStore(chainPEM []byte) error {
	return nil
}

// RemoveLeafFromStore is a no-op on unsupported platforms.
func RemoveLeafFromStore(certPEM []byte) error {
	return nil
}

