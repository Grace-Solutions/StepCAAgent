package ca

import (
	"fmt"

	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
	"github.com/GraceSolutions/StepCAAgent/internal/config"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/state"
)

// SignRequest is the JSON body sent to Step CA's /sign endpoint.
type SignRequest struct {
	CsrPEM    string `json:"csr"`
	OTT       string `json:"ott"`
	NotAfter  string `json:"notAfter,omitempty"`
	NotBefore string `json:"notBefore,omitempty"`
}

// SignResponse is the JSON body returned from /sign.
type SignResponse struct {
	CrtPEM string `json:"crt"`
	CaPEM  string `json:"ca"`
}

// EnrollCertificate generates a key, creates a CSR, and requests a certificate
// from Step CA for the given provisioner config.
func (c *Client) EnrollCertificate(prov config.Provisioner, db *state.DB) error {
	log := logging.Logger()
	log.Info("enrolling certificate", "provisioner", prov.Name)

	// 1. Generate private key
	privKey, keyPEM, err := generateKey(prov.Key)
	if err != nil {
		log.Error("key generation failed", "provisioner", prov.Name, "error", err)
		if db != nil {
			_ = db.RecordAuditEvent("enroll_failed", prov.Name, fmt.Sprintf("key generation: %v", err), "error")
		}
		return fmt.Errorf("generate key for %s: %w", prov.Name, err)
	}
	log.Info("private key generated", "provisioner", prov.Name, "algorithm", prov.Key.Algorithm)

	// 2. Create CSR
	csrPEM, err := createCSR(privKey, prov.Subject)
	if err != nil {
		log.Error("CSR creation failed", "provisioner", prov.Name, "error", err)
		return fmt.Errorf("create CSR for %s: %w", prov.Name, err)
	}
	log.Info("CSR created", "provisioner", prov.Name, "commonName", prov.Subject.CommonName)

	// 3. Get token/password for authentication
	token, err := getAuthToken(prov.Auth)
	if err != nil {
		log.Error("auth token retrieval failed", "provisioner", prov.Name, "error", err)
		return fmt.Errorf("get auth token for %s: %w", prov.Name, err)
	}

	// 4. Submit sign request
	certPEM, chainPEM, err := c.submitSignRequest(csrPEM, token)
	if err != nil {
		log.Error("certificate signing failed", "provisioner", prov.Name, "error", err)
		if db != nil {
			_ = db.RecordAuditEvent("enroll_failed", prov.Name, fmt.Sprintf("sign request: %v", err), "error")
		}
		return fmt.Errorf("sign certificate for %s: %w", prov.Name, err)
	}
	log.Info("certificate signed by CA", "provisioner", prov.Name)

	// 5. Store certificate and key files
	paths := certstore.ResolvePaths(c.CertsDir, prov.Name)

	if err := paths.EnsureDir(); err != nil {
		return err
	}

	if err := paths.WriteCert(certPEM); err != nil {
		return err
	}
	if err := paths.WriteKey(keyPEM); err != nil {
		return err
	}
	if len(chainPEM) > 0 {
		if err := paths.WriteChain(chainPEM); err != nil {
			return err
		}
	}

	// 6. Update state database
	if db != nil {
		cert, _ := parseCertPEM(certPEM)
		if cert != nil {
			_ = db.UpsertCertificate(state.CertRecord{
				Name:        prov.Name,
				Serial:      cert.SerialNumber.String(),
				Subject:     cert.Subject.CommonName,
				Issuer:      cert.Issuer.CommonName,
				NotBefore:   cert.NotBefore,
				NotAfter:    cert.NotAfter,
				StorageType: prov.Storage.Type,
				StoragePath: paths.Certificate,
			})
		}
		_ = db.RecordAuditEvent("enrolled", prov.Name, "certificate enrolled successfully", "success")
	}

	log.Info("certificate enrollment complete", "provisioner", prov.Name,
		"certPath", paths.Certificate, "keyPath", paths.PrivateKey)
	return nil
}

