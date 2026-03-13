package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"

	"github.com/GraceSolutions/StepCAAgent/internal/config"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// generateKey creates a private key based on the provisioner's key config.
// Returns the crypto.Signer and PEM-encoded key bytes.
func generateKey(keyCfg config.Key) (crypto.Signer, []byte, error) {
	log := logging.Logger()
	log.Info("generating private key", "algorithm", keyCfg.Algorithm, "curve", keyCfg.Curve)

	var privKey crypto.Signer
	var keyDER []byte
	var err error

	switch keyCfg.Algorithm {
	case "EC", "ECDSA":
		var curve elliptic.Curve
		switch keyCfg.Curve {
		case "P256":
			curve = elliptic.P256()
		case "P384":
			curve = elliptic.P384()
		case "P521":
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		key, genErr := ecdsa.GenerateKey(curve, rand.Reader)
		if genErr != nil {
			return nil, nil, fmt.Errorf("generate ECDSA key: %w", genErr)
		}
		privKey = key
		keyDER, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal ECDSA key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		log.Info("ECDSA key generated", "curve", keyCfg.Curve)
		return privKey, keyPEM, nil

	case "RSA":
		bits := keyCfg.RSABits
		if bits == 0 {
			bits = 2048
		}
		key, genErr := rsa.GenerateKey(rand.Reader, bits)
		if genErr != nil {
			return nil, nil, fmt.Errorf("generate RSA key: %w", genErr)
		}
		privKey = key
		keyDER = x509.MarshalPKCS1PrivateKey(key)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
		log.Info("RSA key generated", "bits", bits)
		return privKey, keyPEM, nil

	default:
		return nil, nil, fmt.Errorf("unsupported key algorithm: %s", keyCfg.Algorithm)
	}
}

// createCSR creates a PEM-encoded CSR from the private key and subject config.
func createCSR(key crypto.Signer, subj config.Subject) ([]byte, error) {
	log := logging.Logger()
	log.Info("creating CSR", "commonName", subj.CommonName, "dnsNames", len(subj.DNSNames))

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subj.CommonName,
		},
		DNSNames: subj.DNSNames,
	}

	// Parse IP addresses
	for _, ipStr := range subj.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			log.Warn("invalid IP address in subject, skipping", "ip", ipStr)
		}
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	log.Info("CSR created successfully")
	return csrPEM, nil
}

// getAuthToken retrieves the authentication token/password for enrollment.
func getAuthToken(auth config.Auth) (string, error) {
	log := logging.Logger()
	log.Info("retrieving auth token", "type", auth.Type)

	switch auth.Type {
	case "provisioner-password":
		if auth.Password != "" {
			return auth.Password, nil
		}
		if auth.TokenPath != "" {
			data, err := os.ReadFile(auth.TokenPath)
			if err != nil {
				return "", fmt.Errorf("read token file %s: %w", auth.TokenPath, err)
			}
			return string(data), nil
		}
		return "", fmt.Errorf("provisioner-password: no password or tokenPath configured")

	case "bootstrap-token":
		if auth.TokenPath != "" {
			data, err := os.ReadFile(auth.TokenPath)
			if err != nil {
				return "", fmt.Errorf("read token file %s: %w", auth.TokenPath, err)
			}
			return string(data), nil
		}
		return "", fmt.Errorf("bootstrap-token: no tokenPath configured")

	default:
		return "", fmt.Errorf("unsupported auth type: %s", auth.Type)
	}
}

// parseCertPEM parses the first certificate from PEM data.
func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

