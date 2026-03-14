package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
	"github.com/GraceSolutions/StepCAAgent/internal/config"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/state"
)

// RenewCertificate renews a certificate using mTLS with the existing cert/key
// via the Smallstep SDK's Renew method.
func (c *Client) RenewCertificate(prov config.Provisioner, db *state.DB) error {
	log := logging.Logger()
	log.Info("renewing certificate (SDK)", "provisioner", prov.Name)

	paths := certstore.ResolvePaths(c.CertsDir, prov.Name)

	// Load existing cert and key for mTLS
	tlsCert, err := tls.LoadX509KeyPair(paths.Certificate, paths.PrivateKey)
	if err != nil {
		log.Error("could not load existing cert/key for renewal",
			"provisioner", prov.Name,
			"certPath", paths.Certificate,
			"keyPath", paths.PrivateKey,
			"error", err)
		return fmt.Errorf("load cert/key for renewal: %w", err)
	}

	// Build mTLS transport for the SDK Renew call
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	if c.RootCAs != nil {
		tlsCfg.RootCAs = c.RootCAs
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg}

	signResp, err := c.SDK.Renew(tr)
	if err != nil {
		log.Error("SDK renewal failed", "provisioner", prov.Name, "error", err)
		if db != nil {
			_ = db.RecordAuditEvent("renew_failed", prov.Name, fmt.Sprintf("SDK renew: %v", err), "error")
		}
		return fmt.Errorf("renew certificate for %s: %w", prov.Name, err)
	}
	log.Info("certificate renewed by CA", "provisioner", prov.Name)

	// Extract PEM from the SDK response
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signResp.ServerPEM.Raw,
	})

	var chainPEM []byte
	if signResp.CaPEM.Certificate != nil {
		chainPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: signResp.CaPEM.Raw,
		})
	}

	// Write renewed certificate
	if err := paths.WriteCert(certPEM); err != nil {
		return err
	}
	if len(chainPEM) > 0 {
		if err := paths.WriteChain(chainPEM); err != nil {
			return err
		}
	}

	// Update state database
	if db != nil {
		renewed := signResp.ServerPEM.Certificate
		if renewed != nil {
			_ = db.UpsertCertificate(state.CertRecord{
				Name:        prov.Name,
				Serial:      renewed.SerialNumber.String(),
				Subject:     renewed.Subject.CommonName,
				Issuer:      renewed.Issuer.CommonName,
				NotBefore:   renewed.NotBefore,
				NotAfter:    renewed.NotAfter,
				StorageType: prov.Storage.Type,
				StoragePath: paths.Certificate,
			})
		}
		_ = db.RecordAuditEvent("renewed", prov.Name, "certificate renewed successfully", "success")
	}

	log.Info("certificate renewal complete", "provisioner", prov.Name)
	return nil
}

// NeedsRenewal checks if a provisioner's certificate needs renewal.
// certsDir is the certificates base directory (e.g., <base>/certificates).
// Returns whether renewal is needed and the calculated next renewal time.
func NeedsRenewal(certsDir string, prov config.Provisioner) (bool, time.Time, error) {
	log := logging.Logger()
	paths := certstore.ResolvePaths(certsDir, prov.Name)

	certData, err := os.ReadFile(paths.Certificate)
	if err != nil {
		log.Info("no existing certificate found, needs enrollment", "provisioner", prov.Name)
		return true, time.Time{}, nil
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return true, time.Time{}, fmt.Errorf("invalid PEM in cert file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, time.Time{}, fmt.Errorf("parse cert: %w", err)
	}

	renewAt := CalculateRenewalTime(cert, prov.Renewal.RenewBefore)
	now := time.Now()
	needs := now.After(renewAt) || now.Equal(renewAt)

	log.Info("certificate renewal check",
		"provisioner", prov.Name,
		"notBefore", cert.NotBefore.UTC(),
		"notAfter", cert.NotAfter.UTC(),
		"renewAt", renewAt.UTC(),
		"remaining", time.Until(cert.NotAfter),
		"needsRenewal", needs)

	return needs, renewAt, nil
}

// CalculateRenewalTime determines when a certificate should be renewed.
// If renewBefore is "auto" or empty, renewal happens at 2/3 of the certificate's lifetime.
// If renewBefore is a valid duration string, it's subtracted from NotAfter.
func CalculateRenewalTime(cert *x509.Certificate, renewBefore string) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	rb := strings.ToLower(strings.TrimSpace(renewBefore))
	if rb == "" || rb == "auto" {
		return cert.NotBefore.Add(lifetime * 2 / 3)
	}

	d, err := time.ParseDuration(renewBefore)
	if err != nil {
		return cert.NotBefore.Add(lifetime * 2 / 3)
	}

	return cert.NotAfter.Add(-d)
}

