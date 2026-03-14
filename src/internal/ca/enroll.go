package ca

import (
	"encoding/pem"
	"fmt"
	"os"

	stepca "github.com/smallstep/certificates/ca"

	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
	"github.com/GraceSolutions/StepCAAgent/internal/config"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/state"

	"github.com/smallstep/certificates/api"
)

// resolvePassword reads the provisioner password from the Auth config.
// It supports inline passwords and file-based token paths.
func resolvePassword(auth config.Auth) ([]byte, error) {
	if auth.Password != "" {
		return []byte(auth.Password), nil
	}
	if auth.TokenPath != "" {
		data, err := os.ReadFile(auth.TokenPath)
		if err != nil {
			return nil, fmt.Errorf("read password/token file %s: %w", auth.TokenPath, err)
		}
		return data, nil
	}
	return nil, fmt.Errorf("no password or tokenPath configured for provisioner auth")
}

// caProvisionerName returns the Step CA provisioner name to use.
// It delegates to config.Provisioner.CAProvisionerName() which prefers
// caProvisioner over the local name.
func caProvisionerName(prov config.Provisioner) string {
	return prov.CAProvisionerName()
}

// EnrollCertificate generates a key, creates a CSR, obtains a signed JWT
// token via the Smallstep SDK provisioner, and submits a /sign request.
func (c *Client) EnrollCertificate(prov config.Provisioner, db *state.DB) error {
	log := logging.Logger()
	log.Info("enrolling certificate (SDK)", "provisioner", prov.Name)

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
	csrDER, err := createCSRRaw(privKey, prov.Subject)
	if err != nil {
		log.Error("CSR creation failed", "provisioner", prov.Name, "error", err)
		return fmt.Errorf("create CSR for %s: %w", prov.Name, err)
	}
	log.Info("CSR created", "provisioner", prov.Name, "commonName", prov.Subject.CommonName)

	// 3. Resolve provisioner password and create SDK provisioner
	password, err := resolvePassword(prov.Auth)
	if err != nil {
		log.Error("password resolution failed", "provisioner", prov.Name, "error", err)
		return fmt.Errorf("resolve password for %s: %w", prov.Name, err)
	}

	caProvName := caProvisionerName(prov)
	log.Info("creating SDK provisioner for token generation",
		"caProvisioner", caProvName, "caURL", c.BaseURL)

	sdkProv, err := stepca.NewProvisioner(caProvName, "", c.BaseURL+"/", password, c.sdkClientOpts()...)
	if err != nil {
		log.Error("SDK provisioner creation failed", "provisioner", prov.Name, "error", err)
		if db != nil {
			_ = db.RecordAuditEvent("enroll_failed", prov.Name, fmt.Sprintf("SDK provisioner: %v", err), "error")
		}
		return fmt.Errorf("create SDK provisioner for %s: %w", prov.Name, err)
	}

	// 4. Generate a signed JWT (OTT) for the subject and SANs
	sans := collectSANs(prov.Subject)
	token, err := sdkProv.Token(prov.Subject.CommonName, sans...)
	if err != nil {
		log.Error("JWT token generation failed", "provisioner", prov.Name, "error", err)
		return fmt.Errorf("generate token for %s: %w", prov.Name, err)
	}
	log.Info("JWT token generated", "provisioner", prov.Name, "subject", prov.Subject.CommonName)

	// 5. Build and submit sign request via SDK
	signReq := &api.SignRequest{
		CsrPEM: api.NewCertificateRequest(csrDER),
		OTT:    token,
	}

	signResp, err := c.SDK.Sign(signReq)
	if err != nil {
		log.Error("certificate signing failed", "provisioner", prov.Name, "error", err)
		if db != nil {
			_ = db.RecordAuditEvent("enroll_failed", prov.Name, fmt.Sprintf("sign request: %v", err), "error")
		}
		return fmt.Errorf("sign certificate for %s: %w", prov.Name, err)
	}
	log.Info("certificate signed by CA", "provisioner", prov.Name)

	// 6. Extract PEM from the SDK response
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

	// 7. Store certificate and key files on disk
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

	// 7b. Install into Windows Certificate Store if enabled
	storeInstalled := false
	if prov.InstallToStore {
		log.Info("store install requested, importing certificate into Windows Certificate Store",
			"provisioner", prov.Name,
			"leafStore", "MY",
			"intermediateStore", "CA",
			"rootStore", "ROOT")

		friendlyLeaf := fmt.Sprintf("StepCA - %s", prov.Name)
		friendlyIntermediate := fmt.Sprintf("StepCA - %s (Intermediate)", prov.Name)
		friendlyRoot := "StepCA Root CA"

		if err := certstore.InstallLeafToStore(certPEM, friendlyLeaf); err != nil {
			log.Error("store install FAILED for leaf certificate",
				"provisioner", prov.Name, "store", "MY", "error", err)
		} else {
			log.Info("store install SUCCESS: leaf certificate installed",
				"provisioner", prov.Name, "store", "MY", "friendlyName", friendlyLeaf)
			storeInstalled = true
		}

		if len(chainPEM) > 0 {
			if err := certstore.InstallIntermediateToStore(chainPEM, friendlyIntermediate); err != nil {
				log.Error("store install FAILED for intermediate certificate",
					"provisioner", prov.Name, "store", "CA", "error", err)
			} else {
				log.Info("store install SUCCESS: intermediate certificate installed",
					"provisioner", prov.Name, "store", "CA")
			}
		}

		rootPath := certstore.RootCAPath(c.CertsDir)
		if rootPEM, err := os.ReadFile(rootPath); err == nil {
			if err := certstore.InstallRootToStore(rootPEM, friendlyRoot); err != nil {
				log.Error("store install FAILED for root CA",
					"provisioner", prov.Name, "store", "ROOT", "error", err)
			} else {
				log.Info("store install SUCCESS: root CA installed",
					"provisioner", prov.Name, "store", "ROOT")
			}
		}
	}

	// 8. Update state database
	if db != nil {
		cert := signResp.ServerPEM.Certificate
		if cert != nil {
			_ = db.UpsertCertificate(state.CertRecord{
				Name:             prov.Name,
				Serial:           cert.SerialNumber.String(),
				Subject:          cert.Subject.CommonName,
				Issuer:           cert.Issuer.CommonName,
				NotBefore:        cert.NotBefore,
				NotAfter:         cert.NotAfter,
				StorageType:      prov.Storage.Type,
				StoragePath:      paths.Certificate,
				InstalledToStore: storeInstalled,
			})
		}
		_ = db.RecordAuditEvent("enrolled", prov.Name, "certificate enrolled successfully", "success")
	}

	log.Info("certificate enrollment complete",
		"provisioner", prov.Name,
		"certPath", paths.Certificate,
		"keyPath", paths.PrivateKey,
		"installedToStore", storeInstalled)
	return nil
}

// collectSANs gathers all SANs from the Subject config for token generation.
func collectSANs(subj config.Subject) []string {
	var sans []string
	sans = append(sans, subj.DNSNames...)
	sans = append(sans, subj.IPAddresses...)
	sans = append(sans, subj.URIs...)
	sans = append(sans, subj.Emails...)
	return sans
}

