// Package certstore provides Windows Certificate Store operations.
// This file is only compiled on Windows (build tag: windows).
package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// Windows store names
const (
	StoreRoot = "ROOT" // Trusted Root Certification Authorities
	StoreCA   = "CA"   // Intermediate Certification Authorities
	StoreMy   = "MY"   // Personal (leaf / server / client certs)
)

// InstallCertToStore imports a PEM-encoded certificate into the named
// Windows certificate store (e.g., "ROOT", "CA", "MY").
func InstallCertToStore(certPEM []byte, storeName string) error {
	log := logging.Logger()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("winstore: no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("winstore: parse certificate: %w", err)
	}

	log.Info("installing certificate into Windows store",
		"store", storeName,
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber)

	// Open the system certificate store
	storeNameUTF16, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return fmt.Errorf("winstore: UTF16 store name: %w", err)
	}

	store, err := windows.CertOpenSystemStore(0, storeNameUTF16)
	if err != nil {
		return fmt.Errorf("winstore: open store %q: %w", storeName, err)
	}
	defer windows.CertCloseStore(store, 0)

	// Create a CERT_CONTEXT from the DER bytes
	certContext, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		&block.Bytes[0],
		uint32(len(block.Bytes)),
	)
	if err != nil {
		return fmt.Errorf("winstore: create cert context: %w", err)
	}
	defer windows.CertFreeCertificateContext(certContext)

	// Add to store (CERT_STORE_ADD_REPLACE_EXISTING = 3)
	if err := windows.CertAddCertificateContextToStore(store, certContext, 3, nil); err != nil {
		return fmt.Errorf("winstore: add to store %q: %w", storeName, err)
	}

	log.Info("certificate installed into Windows store",
		"store", storeName,
		"subject", cert.Subject.CommonName)
	return nil
}

// IsCertInStore checks whether a certificate (matched by serial number)
// exists in the named Windows certificate store.
func IsCertInStore(certPEM []byte, storeName string) (bool, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, fmt.Errorf("winstore: no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("winstore: parse certificate: %w", err)
	}

	storeNameUTF16, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return false, fmt.Errorf("winstore: UTF16 store name: %w", err)
	}

	store, err := windows.CertOpenSystemStore(0, storeNameUTF16)
	if err != nil {
		return false, fmt.Errorf("winstore: open store %q: %w", storeName, err)
	}
	defer windows.CertCloseStore(store, 0)

	// Enumerate certificates looking for a serial match
	var prev *windows.CertContext
	for {
		cur, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			break // end of store
		}
		if cur == nil {
			break
		}
		prev = cur

		// Parse the store cert and compare serial
		derBytes := unsafe.Slice(cur.EncodedCert, cur.Length)
		storeCert, parseErr := x509.ParseCertificate(derBytes)
		if parseErr != nil {
			continue
		}
		if storeCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

// InstallRootToStore installs a root CA certificate into the Trusted Root store.
func InstallRootToStore(rootPEM []byte) error {
	return InstallCertToStore(rootPEM, StoreRoot)
}

// InstallIntermediateToStore installs an intermediate CA cert into the CA store.
func InstallIntermediateToStore(chainPEM []byte) error {
	return InstallCertToStore(chainPEM, StoreCA)
}

// InstallLeafToStore installs a leaf certificate into the Personal (My) store.
func InstallLeafToStore(certPEM []byte) error {
	return InstallCertToStore(certPEM, StoreMy)
}

