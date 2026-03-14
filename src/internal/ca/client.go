// Package ca provides the Step CA client for bootstrap, enrollment,
// and renewal operations. It wraps the official Smallstep certificates
// SDK (github.com/smallstep/certificates/ca) so that JWK provisioner
// authentication, CSR signing, and mTLS renewal are handled correctly.
package ca

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	stepca "github.com/smallstep/certificates/ca"

	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/permissions"
)

// Client wraps the Smallstep SDK client and adds local file management.
type Client struct {
	BaseURL     string
	Fingerprint string          // optional — manual fingerprint pinning
	CertsDir    string          // <base>/certificates
	SDK         *stepca.Client  // SDK client for /sign, /renew, etc.
	RootCAs     *x509.CertPool // loaded from the stored root CA PEM
}

// NewClient creates a new CA client backed by the Smallstep SDK.
// certsDir is the certificates base directory (e.g., <base>/certificates).
// If a trusted root is already stored on disk it is loaded and used for TLS.
// Fingerprint is optional; when empty, TOFU mode is used.
func NewClient(caURL, certsDir, fingerprint string) (*Client, error) {
	log := logging.Logger()
	log.Info("creating CA client (SDK)", "url", caURL, "certsDir", certsDir)

	c := &Client{
		BaseURL:     strings.TrimRight(caURL, "/"),
		Fingerprint: fingerprint,
		CertsDir:    certsDir,
	}

	// Build SDK client options
	opts := c.sdkClientOpts()

	// Try loading existing root into the pool for non-SDK operations
	rootPath := certstore.RootCAPath(certsDir)
	if data, err := os.ReadFile(rootPath); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(data) {
			c.RootCAs = pool
			log.Info("loaded existing root CA", "path", rootPath)
		}
	}

	sdkClient, err := stepca.NewClient(c.BaseURL+"/", opts...)
	if err != nil {
		return nil, fmt.Errorf("create SDK client: %w", err)
	}
	c.SDK = sdkClient

	log.Info("CA client created (SDK)", "url", caURL)
	return c, nil
}

// sdkClientOpts returns the ClientOption slice for the SDK client.
func (c *Client) sdkClientOpts() []stepca.ClientOption {
	rootPath := certstore.RootCAPath(c.CertsDir)
	if _, err := os.Stat(rootPath); err == nil {
		return []stepca.ClientOption{stepca.WithRootFile(rootPath)}
	}
	// No root on disk yet — bootstrap with insecure TLS (fingerprint verified later)
	return []stepca.ClientOption{stepca.WithInsecure()}
}

// FetchRootCertificate downloads the root certificate from the CA.
// If a fingerprint is configured it uses the SDK's /root/{fingerprint} endpoint.
// Otherwise it tries the SDK's TOFU flow, and falls back to a direct insecure
// GET to /roots (which returns all root CAs without needing a fingerprint).
func (c *Client) FetchRootCertificate() ([]byte, error) {
	log := logging.Logger()
	log.Info("fetching root certificate from CA", "url", c.BaseURL)

	// Use an insecure SDK client for the initial root fetch
	insecureClient, err := stepca.NewClient(c.BaseURL+"/", stepca.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("create insecure client for root fetch: %w", err)
	}

	// If a fingerprint is explicitly configured, use the SDK's /root/{fingerprint} endpoint.
	if c.Fingerprint != "" {
		rootResp, err := insecureClient.Root(c.Fingerprint)
		if err != nil {
			return nil, fmt.Errorf("fetch root certificate: %w", err)
		}
		rootPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootResp.RootPEM.Raw,
		})
		log.Info("root certificate fetched (fingerprint)", "subject", rootResp.RootPEM.Subject, "bytes", len(rootPEM))
		return rootPEM, nil
	}

	// TOFU mode — try SDK RootFingerprint first
	fp, err := insecureClient.RootFingerprint()
	if err == nil {
		log.Warn("no fingerprint configured — discovered via TOFU", "fingerprint", fp)
		rootResp, err := insecureClient.Root(fp)
		if err == nil {
			rootPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: rootResp.RootPEM.Raw,
			})
			log.Info("root certificate fetched (TOFU)", "subject", rootResp.RootPEM.Subject, "bytes", len(rootPEM))
			return rootPEM, nil
		}
		log.Warn("SDK Root() failed after TOFU fingerprint, falling back to /roots", "error", err)
	} else {
		log.Warn("SDK RootFingerprint failed, falling back to /roots", "error", err)
	}

	// Fallback: fetch directly from /roots endpoint (no fingerprint needed)
	rootPEM, err := c.fetchRootsInsecure()
	if err != nil {
		return nil, fmt.Errorf("fetch roots (TOFU fallback): %w", err)
	}
	return rootPEM, nil
}

// fetchRootsInsecure performs an insecure HTTPS GET to the CA's /roots endpoint,
// which returns a JSON response with a "certificates" array of PEM strings.
// This is the TOFU fallback when SDK fingerprint discovery fails (common with
// private CAs that use an intermediate for their TLS cert).
func (c *Client) fetchRootsInsecure() ([]byte, error) {
	log := logging.Logger()

	url := c.BaseURL + "/roots"
	log.Info("fetching roots via insecure GET", "url", url)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}

	// Step CA /roots returns: {"crts": ["-----BEGIN CERTIFICATE-----\n..."]}
	var rootsResp struct {
		Crts []string `json:"crts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rootsResp); err != nil {
		return nil, fmt.Errorf("decode /roots response: %w", err)
	}

	if len(rootsResp.Crts) == 0 {
		return nil, fmt.Errorf("no root certificates returned from %s", url)
	}

	// Use the first root certificate
	rootPEMStr := rootsResp.Crts[0]
	block, _ := pem.Decode([]byte(rootPEMStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in root certificate from /roots")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root from /roots: %w", err)
	}

	hash := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(hash[:])

	log.Info("root certificate fetched via /roots",
		"subject", cert.Subject,
		"fingerprint", fp,
		"bytes", len(rootPEMStr))

	return []byte(rootPEMStr), nil
}

// VerifyFingerprint checks that the PEM root certificate matches the expected fingerprint.
func VerifyFingerprint(rootPEM []byte, expected string) error {
	log := logging.Logger()
	log.Info("verifying root certificate fingerprint")

	block, _ := pem.Decode(rootPEM)
	if block == nil {
		return fmt.Errorf("no PEM block found in root certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse root certificate: %w", err)
	}

	hash := sha256.Sum256(cert.Raw)
	actual := "SHA256:" + strings.ToUpper(hex.EncodeToString(hash[:]))

	exp := strings.ToUpper(strings.TrimSpace(expected))
	if !strings.HasPrefix(exp, "SHA256:") {
		exp = "SHA256:" + exp
	}

	if actual != exp {
		log.Error("root certificate fingerprint mismatch", "expected", exp, "actual", actual)
		return fmt.Errorf("fingerprint mismatch: expected %s, got %s", exp, actual)
	}

	log.Info("root certificate fingerprint verified", "fingerprint", actual, "subject", cert.Subject)
	return nil
}

// TrustRoot fetches, verifies, and stores the CA root certificate.
func (c *Client) TrustRoot() error {
	log := logging.Logger()
	log.Info("beginning root trust operation")

	rootPEM, err := c.FetchRootCertificate()
	if err != nil {
		return err
	}

	if c.Fingerprint != "" {
		if err := VerifyFingerprint(rootPEM, c.Fingerprint); err != nil {
			return err
		}
	} else {
		log.Warn("no fingerprint configured, TOFU verification used")
	}

	// Store the root certificate
	rootPath := certstore.RootCAPath(c.CertsDir)

	dir := filepath.Dir(rootPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}

	if err := os.WriteFile(rootPath, rootPEM, 0600); err != nil {
		return fmt.Errorf("write root CA: %w", err)
	}
	_ = permissions.EnforceRestrictive(rootPath)

	// Reload with the new root
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	c.RootCAs = pool

	// Recreate SDK client with the new root
	sdkClient, err := stepca.NewClient(c.BaseURL+"/", stepca.WithRootFile(rootPath))
	if err != nil {
		return fmt.Errorf("recreate SDK client with new root: %w", err)
	}
	c.SDK = sdkClient

	log.Info("root CA trusted and stored", "path", rootPath)
	return nil
}

// IsRootExpiring checks if the stored root CA will expire within the given duration.
func (c *Client) IsRootExpiring(within time.Duration) (bool, error) {
	log := logging.Logger()
	rootPath := certstore.RootCAPath(c.CertsDir)

	data, err := os.ReadFile(rootPath)
	if err != nil {
		return false, fmt.Errorf("read root CA: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return false, fmt.Errorf("no PEM block in root CA file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse root CA: %w", err)
	}

	expiring := time.Until(cert.NotAfter) < within
	log.Info("root CA expiry check",
		"notAfter", cert.NotAfter.UTC(),
		"withinDuration", within,
		"expiring", expiring)

	return expiring, nil
}

// RevokeCertificate revokes a certificate by serial number using mTLS.
func (c *Client) RevokeCertificate(serial, certPath string) error {
	log := logging.Logger()
	log.Info("revoking certificate", "serial", serial)

	if serial == "" {
		return fmt.Errorf("revoke: serial number is required")
	}

	// Build mTLS HTTP client if we have the cert files
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if certPath != "" {
		keyPath := filepath.Join(filepath.Dir(certPath), certstore.KeyFile)
		tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			log.Warn("could not load cert for mTLS revocation, trying without", "error", err)
		} else {
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				RootCAs:      c.RootCAs,
			}
			httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		}
	}

	payload := fmt.Sprintf(`{"serial":"%s","reasonCode":0}`, serial)
	url := c.BaseURL + "/1.0/revoke"

	resp, err := httpClient.Post(url, "application/json", strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("revoke: POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke: POST %s returned HTTP %d", url, resp.StatusCode)
	}

	log.Info("certificate revoked successfully", "serial", serial)
	return nil
}

// RefreshRoot re-fetches and re-trusts the root if it's expiring.
func (c *Client) RefreshRoot(within time.Duration) error {
	log := logging.Logger()
	log.Info("checking if root CA needs refresh")

	expiring, err := c.IsRootExpiring(within)
	if err != nil {
		log.Warn("could not check root expiry, attempting trust", "error", err)
		return c.TrustRoot()
	}

	if expiring {
		log.Info("root CA is expiring, refreshing")
		return c.TrustRoot()
	}

	log.Info("root CA is still valid, no refresh needed")
	return nil
}

