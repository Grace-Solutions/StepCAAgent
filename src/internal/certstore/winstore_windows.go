// Package certstore provides Windows Certificate Store operations.
// This file is only compiled on Windows (build tag: windows).
package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"syscall"
	"unicode/utf16"
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

// CryptoAPI constants not in x/sys/windows
const (
	CERT_FRIENDLY_NAME_PROP_ID = 11
)

// Lazy-loaded CryptoAPI functions not available in x/sys/windows
var (
	modCrypt32                        = syscall.NewLazyDLL("crypt32.dll")
	procCertSetCertificateContextProp = modCrypt32.NewProc("CertSetCertificateContextProperty")
)

// CRYPT_DATA_BLOB represents the Windows CRYPT_DATA_BLOB structure.
type cryptDataBlob struct {
	Size uint32
	Data *byte
}

// InstallCertToStore imports a PEM-encoded certificate into the named
// Windows certificate store (e.g., "ROOT", "CA", "MY"). If friendlyName
// is non-empty, it is set as the certificate's Friendly Name property.
func InstallCertToStore(certPEM []byte, storeName, friendlyName string) error {
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
		"scope", "Local Machine",
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber,
		"friendlyName", friendlyName)

	// Open the Local Machine system certificate store
	storeNameUTF16, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return fmt.Errorf("winstore: UTF16 store name: %w", err)
	}

	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(storeNameUTF16)),
	)
	if err != nil {
		return fmt.Errorf("winstore: open store %q (Local Machine): %w", storeName, err)
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

	// Set friendly name property before adding to store
	if friendlyName != "" {
		if err := setFriendlyName(certContext, friendlyName); err != nil {
			log.Warn("failed to set friendly name, continuing without it",
				"friendlyName", friendlyName, "error", err)
		}
	}

	// Add to store (CERT_STORE_ADD_REPLACE_EXISTING = 3)
	if err := windows.CertAddCertificateContextToStore(store, certContext, 3, nil); err != nil {
		return fmt.Errorf("winstore: add to store %q: %w", storeName, err)
	}

	log.Info("certificate installed into Windows store",
		"store", storeName,
		"subject", cert.Subject.CommonName,
		"friendlyName", friendlyName)
	return nil
}

// setFriendlyName sets the CERT_FRIENDLY_NAME_PROP_ID property on a cert context.
func setFriendlyName(ctx *windows.CertContext, name string) error {
	// The friendly name must be a null-terminated UTF-16 string
	utf16Str := utf16.Encode([]rune(name + "\x00"))
	blob := cryptDataBlob{
		Size: uint32(len(utf16Str) * 2),
		Data: (*byte)(unsafe.Pointer(&utf16Str[0])),
	}
	r1, _, err := procCertSetCertificateContextProp.Call(
		uintptr(unsafe.Pointer(ctx)),
		uintptr(CERT_FRIENDLY_NAME_PROP_ID),
		0,
		uintptr(unsafe.Pointer(&blob)),
	)
	if r1 == 0 {
		return fmt.Errorf("CertSetCertificateContextProperty: %w", err)
	}
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

	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(storeNameUTF16)),
	)
	if err != nil {
		return false, fmt.Errorf("winstore: open store %q (Local Machine): %w", storeName, err)
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

// RemoveCertFromStore removes a PEM-encoded certificate from the named
// Windows certificate store, matched by serial number.
func RemoveCertFromStore(certPEM []byte, storeName string) error {
	log := logging.Logger()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("winstore: no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("winstore: parse certificate: %w", err)
	}

	log.Info("removing certificate from Windows store",
		"store", storeName,
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber)

	storeNameUTF16, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return fmt.Errorf("winstore: UTF16 store name: %w", err)
	}

	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(storeNameUTF16)),
	)
	if err != nil {
		return fmt.Errorf("winstore: open store %q (Local Machine): %w", storeName, err)
	}
	defer windows.CertCloseStore(store, 0)

	// Enumerate and delete matching certificates
	removed := 0
	var prev *windows.CertContext
	for {
		cur, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			break
		}
		if cur == nil {
			break
		}

		derBytes := unsafe.Slice(cur.EncodedCert, cur.Length)
		storeCert, parseErr := x509.ParseCertificate(derBytes)
		if parseErr != nil {
			prev = cur
			continue
		}

		if storeCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			// CertDeleteCertificateFromStore frees the context and
			// invalidates 'cur', so we must NOT use it as prev.
			// Pass nil as prev on the next iteration to restart enumeration.
			dupCtx := windows.CertDuplicateCertificateContext(cur)
			if dupCtx == nil {
				prev = cur
				continue
			}
			if delErr := windows.CertDeleteCertificateFromStore(dupCtx); delErr != nil {
				log.Error("failed to delete certificate from store",
					"store", storeName,
					"subject", storeCert.Subject.CommonName,
					"error", delErr)
			} else {
				removed++
				log.Info("certificate deleted from Windows store",
					"store", storeName,
					"subject", storeCert.Subject.CommonName,
					"serial", storeCert.SerialNumber)
			}
			// Restart enumeration since the store was modified
			prev = nil
			continue
		}
		prev = cur
	}

	if removed == 0 {
		log.Info("certificate not found in Windows store, nothing to remove",
			"store", storeName,
			"subject", cert.Subject.CommonName)
	} else {
		log.Info("certificate removal complete",
			"store", storeName,
			"removed", removed)
	}
	return nil
}

// InstallRootToStore installs a root CA certificate into the Trusted Root store.
func InstallRootToStore(rootPEM []byte, friendlyName string) error {
	return InstallCertToStore(rootPEM, StoreRoot, friendlyName)
}

// InstallIntermediateToStore installs an intermediate CA cert into the CA store.
func InstallIntermediateToStore(chainPEM []byte, friendlyName string) error {
	return InstallCertToStore(chainPEM, StoreCA, friendlyName)
}

// InstallLeafToStore installs a leaf certificate into the Personal (My) store.
func InstallLeafToStore(certPEM []byte, friendlyName string) error {
	return InstallCertToStore(certPEM, StoreMy, friendlyName)
}

// RemoveRootFromStore removes a root CA certificate from the Trusted Root store.
func RemoveRootFromStore(rootPEM []byte) error {
	return RemoveCertFromStore(rootPEM, StoreRoot)
}

// RemoveIntermediateFromStore removes an intermediate CA cert from the CA store.
func RemoveIntermediateFromStore(chainPEM []byte) error {
	return RemoveCertFromStore(chainPEM, StoreCA)
}

// RemoveLeafFromStore removes a leaf certificate from the Personal (My) store.
func RemoveLeafFromStore(certPEM []byte) error {
	return RemoveCertFromStore(certPEM, StoreMy)
}

