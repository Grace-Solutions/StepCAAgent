package ca

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
	"github.com/GraceSolutions/StepCAAgent/internal/config"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/state"
)

// submitSignRequest sends a CSR to the CA's /sign endpoint.
func (c *Client) submitSignRequest(csrPEM []byte, token string) (certPEM, chainPEM []byte, err error) {
	log := logging.Logger()
	url := c.BaseURL + "/sign"
	log.Info("submitting sign request", "url", url)

	reqBody := SignRequest{
		CsrPEM: string(csrPEM),
		OTT:    token,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal sign request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("create sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.Error("sign request failed", "url", url, "error", err)
		return nil, nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Error("sign request returned error",
			"url", url,
			"httpStatus", resp.StatusCode,
			"body", string(respBody))
		return nil, nil, fmt.Errorf("POST %s returned HTTP %d: %s", url, resp.StatusCode, string(respBody))
	}

	var signResp SignResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return nil, nil, fmt.Errorf("parse sign response: %w", err)
	}

	log.Info("sign request successful", "url", url, "httpStatus", resp.StatusCode)
	return []byte(signResp.CrtPEM), []byte(signResp.CaPEM), nil
}

// RenewCertificate renews a certificate using mTLS with the existing cert/key.
func (c *Client) RenewCertificate(prov config.Provisioner, db *state.DB) error {
	log := logging.Logger()
	log.Info("renewing certificate", "provisioner", prov.Name)

	paths := certstore.ResolvePaths(c.CertsDir, prov.Name)

	// Load existing cert and key for mTLS
	cert, err := tls.LoadX509KeyPair(paths.Certificate, paths.PrivateKey)
	if err != nil {
		log.Error("could not load existing cert/key for renewal",
			"provisioner", prov.Name,
			"certPath", paths.Certificate,
			"keyPath", paths.PrivateKey,
			"error", err)
		return fmt.Errorf("load cert/key for renewal: %w", err)
	}

	// Build mTLS client
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if c.RootCAs != nil {
		tlsCfg.RootCAs = c.RootCAs
	}

	renewClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	// POST /renew
	url := c.BaseURL + "/renew"
	log.Info("submitting renewal request", "url", url)

	resp, err := renewClient.Post(url, "application/json", nil)
	if err != nil {
		log.Error("renewal request failed", "url", url, "error", err)
		if db != nil {
			_ = db.RecordAuditEvent("renew_failed", prov.Name, fmt.Sprintf("POST %s: %v", url, err), "error")
		}
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Error("renewal returned error",
			"url", url,
			"httpStatus", resp.StatusCode,
			"body", string(respBody))
		if db != nil {
			_ = db.RecordAuditEvent("renew_failed", prov.Name,
				fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBody)), "error")
		}
		return fmt.Errorf("POST %s returned HTTP %d", url, resp.StatusCode)
	}

	var signResp SignResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return fmt.Errorf("parse renewal response: %w", err)
	}

	// Write renewed certificate
	if err := paths.WriteCert([]byte(signResp.CrtPEM)); err != nil {
		return err
	}
	if signResp.CaPEM != "" {
		if err := paths.WriteChain([]byte(signResp.CaPEM)); err != nil {
			return err
		}
	}

	// Update state database
	if db != nil {
		renewed, _ := parseCertPEM([]byte(signResp.CrtPEM))
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
		// Auto: renew at 2/3 of the certificate lifetime
		return cert.NotBefore.Add(lifetime * 2 / 3)
	}

	d, err := time.ParseDuration(renewBefore)
	if err != nil {
		// Invalid duration, fall back to auto (2/3 lifetime)
		return cert.NotBefore.Add(lifetime * 2 / 3)
	}

	return cert.NotAfter.Add(-d)
}

