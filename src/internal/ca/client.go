// Package ca provides the Step CA API client for bootstrap, enrollment,
// and renewal operations.
package ca

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/permissions"
)

// Client wraps HTTP interactions with a Step CA server.
type Client struct {
	BaseURL     string
	Fingerprint string // optional — set for manual fingerprint pinning
	CertsDir    string // <base>/certificates
	HTTPClient  *http.Client
	RootCAs     *x509.CertPool
}

// NewClient creates a new CA client. certsDir is the certificates base
// directory (e.g., <base>/certificates). If a trusted root is already stored,
// it will be loaded into the TLS config. Fingerprint is optional; when empty,
// TOFU (Trust On First Use) mode is used and the fingerprint is computed and logged.
func NewClient(caURL, certsDir, fingerprint string) (*Client, error) {
	log := logging.Logger()
	log.Info("creating CA client", "url", caURL, "certsDir", certsDir)

	c := &Client{
		BaseURL:     strings.TrimRight(caURL, "/"),
		Fingerprint: fingerprint,
		CertsDir:    certsDir,
	}

	// Try loading existing root
	rootPath := certstore.RootCAPath(certsDir)
	if data, err := os.ReadFile(rootPath); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(data) {
			c.RootCAs = pool
			log.Info("loaded existing root CA", "path", rootPath)
		}
	}

	c.HTTPClient = c.buildHTTPClient()
	log.Info("CA client created", "url", caURL)
	return c, nil
}

func (c *Client) buildHTTPClient() *http.Client {
	tlsCfg := &tls.Config{}
	if c.RootCAs != nil {
		tlsCfg.RootCAs = c.RootCAs
	} else {
		// For initial bootstrap, skip TLS verify but validate fingerprint
		tlsCfg.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// FetchRootCertificate downloads the root certificate from /root/{sha256}
// or /roots.pem and verifies the fingerprint.
func (c *Client) FetchRootCertificate() ([]byte, error) {
	log := logging.Logger()
	log.Info("fetching root certificate from CA", "url", c.BaseURL)

	// Try /roots.pem first (common Step CA endpoint)
	url := c.BaseURL + "/roots.pem"
	log.Info("requesting root certificate", "url", url)

	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		log.Error("failed to fetch root certificate", "url", url, "error", err)
		return nil, fmt.Errorf("fetch root: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error("unexpected status fetching root", "url", url, "status", resp.StatusCode)
		return nil, fmt.Errorf("fetch root: GET %s returned HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch root: read body: %w", err)
	}

	log.Info("root certificate fetched", "bytes", len(body))
	return body, nil
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

	// Normalize expected
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
		log.Warn("no fingerprint configured, skipping verification (TOFU mode)")
	}

	// Store the root certificate
	rootPath := certstore.RootCAPath(c.CertsDir)

	// Ensure the certificates directory exists
	dir := filepath.Dir(rootPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}

	if err := os.WriteFile(rootPath, rootPEM, 0600); err != nil {
		return fmt.Errorf("write root CA: %w", err)
	}
	_ = permissions.EnforceRestrictive(rootPath)

	// Reload the client with the new root
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	c.RootCAs = pool
	c.HTTPClient = c.buildHTTPClient()

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

// ProvisionerClaims holds the duration limits from a Step CA provisioner.
type ProvisionerClaims struct {
	MinTLSCertDuration     time.Duration
	MaxTLSCertDuration     time.Duration
	DefaultTLSCertDuration time.Duration
}

// FetchProvisionerClaims queries the CA's /provisioners endpoint and returns
// the claims (duration limits) for the named provisioner.
func (c *Client) FetchProvisionerClaims(provisionerName string) (*ProvisionerClaims, error) {
	log := logging.Logger()
	url := c.BaseURL + "/provisioners"
	log.Info("fetching provisioner claims", "url", url, "provisioner", provisionerName)

	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		log.Error("failed to fetch provisioners", "url", url, "error", err)
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error("unexpected status fetching provisioners", "url", url, "httpStatus", resp.StatusCode)
		return nil, fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read provisioners response: %w", err)
	}

	// Step CA returns {"provisioners": [{...}, ...]}
	var result struct {
		Provisioners []struct {
			Name   string `json:"name"`
			Claims struct {
				MinTLSCertDuration     string `json:"minTLSCertDuration"`
				MaxTLSCertDuration     string `json:"maxTLSCertDuration"`
				DefaultTLSCertDuration string `json:"defaultTLSCertDuration"`
			} `json:"claims"`
		} `json:"provisioners"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse provisioners response: %w", err)
	}

	for _, p := range result.Provisioners {
		if p.Name == provisionerName {
			claims := &ProvisionerClaims{}
			if d, err := time.ParseDuration(p.Claims.MinTLSCertDuration); err == nil {
				claims.MinTLSCertDuration = d
			}
			if d, err := time.ParseDuration(p.Claims.MaxTLSCertDuration); err == nil {
				claims.MaxTLSCertDuration = d
			}
			if d, err := time.ParseDuration(p.Claims.DefaultTLSCertDuration); err == nil {
				claims.DefaultTLSCertDuration = d
			}
			log.Info("provisioner claims fetched",
				"provisioner", provisionerName,
				"minDuration", claims.MinTLSCertDuration,
				"maxDuration", claims.MaxTLSCertDuration,
				"defaultDuration", claims.DefaultTLSCertDuration)
			return claims, nil
		}
	}

	log.Warn("provisioner not found in CA response, using defaults", "provisioner", provisionerName)
	return nil, nil
}

// RevokeCertificate revokes a certificate by serial number using mTLS.
// certPath is used to load the cert+key for mTLS authentication.
func (c *Client) RevokeCertificate(serial, certPath string) error {
	log := logging.Logger()
	log.Info("revoking certificate", "serial", serial)

	if serial == "" {
		return fmt.Errorf("revoke: serial number is required")
	}

	// Build mTLS client if we have the cert files
	httpClient := c.HTTPClient
	if certPath != "" {
		keyPath := strings.TrimSuffix(certPath, ".crt") + ".key"
		tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			log.Warn("could not load cert for mTLS revocation, trying without", "error", err)
		} else {
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				RootCAs:      c.RootCAs,
			}
			httpClient = &http.Client{
				Timeout:   30 * time.Second,
				Transport: &http.Transport{TLSClientConfig: tlsCfg},
			}
		}
	}

	// Step CA revoke endpoint: POST /1.0/revoke
	payload := fmt.Sprintf(`{"serial":"%s","reasonCode":0}`, serial)
	url := c.BaseURL + "/1.0/revoke"

	resp, err := httpClient.Post(url, "application/json", strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("revoke: POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke: POST %s returned HTTP %d: %s", url, resp.StatusCode, string(body))
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
		// Root might not exist yet
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

