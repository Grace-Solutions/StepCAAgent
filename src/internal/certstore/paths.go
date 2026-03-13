// Package certstore manages certificate file paths and storage layout.
// Layout: <baseDir>/certificates/<provisioner_name>/ with fixed filenames.
package certstore

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/permissions"
)

const (
	CertsDirName = "certificates"
	CertFile     = "certificate.crt"
	KeyFile      = "private.key"
	ChainFile    = "chain.crt"
	RootFile     = "root_ca.crt"
)

// Paths holds the resolved file paths for a provisioner's certificate files.
type Paths struct {
	BaseDir     string // <baseDir>/certificates/<provisioner>/
	Certificate string
	PrivateKey  string
	Chain       string
}

// ResolvePaths returns the file paths for a provisioner under the given
// certificates directory. All filenames are standardized.
func ResolvePaths(certsDir, provisionerName string) *Paths {
	log := logging.Logger()
	dir := filepath.Join(certsDir, provisionerName)
	p := &Paths{
		BaseDir:     dir,
		Certificate: filepath.Join(dir, CertFile),
		PrivateKey:  filepath.Join(dir, KeyFile),
		Chain:       filepath.Join(dir, ChainFile),
	}
	log.Info("certificate paths resolved",
		"provisioner", provisionerName,
		"cert", p.Certificate,
		"key", p.PrivateKey,
		"chain", p.Chain)
	return p
}

// EnsureDir creates the provisioner's certificate directory with restrictive permissions.
func (p *Paths) EnsureDir() error {
	log := logging.Logger()
	log.Info("ensuring certificate directory exists", "dir", p.BaseDir)

	if err := os.MkdirAll(p.BaseDir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", p.BaseDir, err)
	}

	if err := permissions.EnforceRestrictive(p.BaseDir); err != nil {
		log.Warn("could not enforce restrictive permissions on cert dir", "dir", p.BaseDir, "error", err)
	}

	log.Info("certificate directory ready", "dir", p.BaseDir)
	return nil
}

// RootCAPath returns the path to the trusted root CA certificate
// under the given certificates directory.
func RootCAPath(certsDir string) string {
	return filepath.Join(certsDir, RootFile)
}

// WriteCert writes certificate data to the provisioner's cert file with restrictive permissions.
func (p *Paths) WriteCert(certPEM []byte) error {
	log := logging.Logger()
	log.Info("writing certificate", "path", p.Certificate)

	if err := os.WriteFile(p.Certificate, certPEM, 0600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	_ = permissions.EnforceRestrictive(p.Certificate)

	log.Info("certificate written successfully", "path", p.Certificate)
	return nil
}

// WriteKey writes private key data with restrictive permissions.
func (p *Paths) WriteKey(keyPEM []byte) error {
	log := logging.Logger()
	log.Info("writing private key", "path", p.PrivateKey)

	if err := os.WriteFile(p.PrivateKey, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	_ = permissions.EnforceRestrictive(p.PrivateKey)

	log.Info("private key written successfully", "path", p.PrivateKey)
	return nil
}

// WriteChain writes the certificate chain with restrictive permissions.
func (p *Paths) WriteChain(chainPEM []byte) error {
	log := logging.Logger()
	log.Info("writing certificate chain", "path", p.Chain)

	if err := os.WriteFile(p.Chain, chainPEM, 0600); err != nil {
		return fmt.Errorf("write chain: %w", err)
	}
	_ = permissions.EnforceRestrictive(p.Chain)

	log.Info("certificate chain written successfully", "path", p.Chain)
	return nil
}

