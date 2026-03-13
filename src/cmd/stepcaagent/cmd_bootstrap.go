package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/GraceSolutions/StepCAAgent/internal/ca"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// defaultCertsDir returns <binary_dir>/data/certificates as the default certificates directory.
func defaultCertsDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "data", "certificates")
	}
	return filepath.Join(filepath.Dir(exe), "data", "certificates")
}

func bootstrapCommand() *cli.Command {
	return &cli.Command{
		Name:  "bootstrap",
		Usage: "CA trust bootstrap operations",
		Subcommands: []*cli.Command{
			{
				Name:  "fingerprint",
				Usage: "Fetch and display the CA root fingerprint",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "ca-url",
						Usage:    "Step CA URL",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					if err := logging.Init(logging.Config{ToStderr: true, Level: "info"}); err != nil {
						return err
					}
					defer logging.Close()

					client, err := ca.NewClient(c.String("ca-url"), defaultCertsDir(), "")
					if err != nil {
						return fmt.Errorf("create CA client: %w", err)
					}

					rootPEM, err := client.FetchRootCertificate()
					if err != nil {
						return fmt.Errorf("fetch root: %w", err)
					}

					block, _ := pem.Decode(rootPEM)
					if block == nil {
						return fmt.Errorf("no PEM block in root certificate")
					}
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						return fmt.Errorf("parse root: %w", err)
					}

					hash := sha256.Sum256(cert.Raw)
					fp := "SHA256:" + strings.ToUpper(hex.EncodeToString(hash[:]))
					fmt.Printf("Root CA Fingerprint: %s\n", fp)
					fmt.Printf("Subject: %s\n", cert.Subject)
					fmt.Printf("Not After: %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
					return nil
				},
			},
			{
				Name:  "trust",
				Usage: "Trust management",
				Subcommands: []*cli.Command{
					{
						Name:  "install",
						Usage: "Install CA root trust",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "ca-url", Usage: "Step CA URL", Required: true},
							&cli.StringFlag{Name: "fingerprint", Usage: "Expected root fingerprint", Required: true},
						},
						Action: func(c *cli.Context) error {
							if err := logging.Init(logging.Config{ToStderr: true, Level: "info"}); err != nil {
								return err
							}
							defer logging.Close()

							client, err := ca.NewClient(c.String("ca-url"), defaultCertsDir(), c.String("fingerprint"))
							if err != nil {
								return fmt.Errorf("create CA client: %w", err)
							}

							if err := client.TrustRoot(); err != nil {
								return fmt.Errorf("trust install: %w", err)
							}
							fmt.Println("CA root trust installed successfully.")
							return nil
						},
					},
					{
						Name:  "refresh",
						Usage: "Refresh CA root trust",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "ca-url", Usage: "Step CA URL", Required: true},
						},
						Action: func(c *cli.Context) error {
							if err := logging.Init(logging.Config{ToStderr: true, Level: "info"}); err != nil {
								return err
							}
							defer logging.Close()

							client, err := ca.NewClient(c.String("ca-url"), defaultCertsDir(), "")
							if err != nil {
								return fmt.Errorf("create CA client: %w", err)
							}

							if err := client.RefreshRoot(30 * 24 * time.Hour); err != nil {
								return fmt.Errorf("trust refresh: %w", err)
							}
							fmt.Println("CA root trust refreshed.")
							return nil
						},
					},
				},
			},
		},
	}
}

