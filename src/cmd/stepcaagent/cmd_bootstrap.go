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
	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
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
		Usage: "Fetch the CA root certificate and store it locally; optionally install into the platform trust store",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "ca-url",
				Usage:    "Step CA server URL (required)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "fingerprint",
				Usage: "Expected root CA fingerprint for verification (auto TOFU if omitted)",
			},
			&cli.BoolFlag{
				Name:  "installtostore",
				Usage: "Install the root CA into the platform trust store after fetching",
			},
			&cli.StringFlag{
				Name:  "store",
				Usage: "Trust store target: auto (default), localmachine, currentuser, or both",
				Value: string(certstore.ScopeAuto),
			},
		},
		Action: bootstrapAction,
		Subcommands: []*cli.Command{
			bootstrapFingerprintSubcommand(),
			bootstrapTrustSubcommand(),
		},
	}
}

// bootstrapAction is the direct action for `stepcaagent bootstrap --ca-url <url>`.
// It fetches the root certificate and saves it to disk. If --installtostore is
// specified, it also installs the root into the platform trust store using the
// scope from --store (defaults to "auto" which detects admin/root privileges).
func bootstrapAction(c *cli.Context) error {
	// Reject use with --config / --config-url
	if c.IsSet("config") || c.IsSet("config-url") {
		return fmt.Errorf("bootstrap cannot be used with --config or --config-url; provide --ca-url only")
	}

	if err := logging.Init(logging.Config{ToStderr: true, Level: "info"}); err != nil {
		return err
	}
	defer logging.Close()

	log := logging.Logger()

	caURL := c.String("ca-url")
	fingerprint := c.String("fingerprint")
	installToStore := c.Bool("installtostore")
	scope := certstore.StoreScope(c.String("store"))
	if !scope.IsValid() {
		return fmt.Errorf("invalid --store %q; valid values: %s",
			scope, strings.Join(certstore.ValidScopes(), ", "))
	}

	certsDir := defaultCertsDir()
	log.Info("bootstrap starting",
		"caURL", caURL,
		"fingerprint", fingerprint,
		"installToStore", installToStore,
		"store", scope,
		"certsDir", certsDir)

	// 1. Create CA client
	client, err := ca.NewClient(caURL, certsDir, fingerprint)
	if err != nil {
		return fmt.Errorf("create CA client: %w", err)
	}

	// 2. Fetch and store root certificate to disk
	if err := client.TrustRoot(); err != nil {
		return fmt.Errorf("fetch/store root CA: %w", err)
	}

	// 3. Read the stored root PEM back
	rootPath := certstore.RootCAPath(certsDir)
	rootPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return fmt.Errorf("read stored root CA %s: %w", rootPath, err)
	}

	// 4. Optionally install into platform trust store
	if installToStore {
		resolved := certstore.ResolveAutoScope(scope)
		log.Info("installing root CA to trust store", "scope", resolved)
		if err := certstore.InstallRootToStoreScoped(rootPEM, "StepCA Root CA", resolved); err != nil {
			return fmt.Errorf("install root CA to trust store (scope=%s): %w", resolved, err)
		}
		fmt.Printf("Trust store:         installed (scope: %s)\n", resolved)
	} else {
		fmt.Println("Trust store:         skipped (use --installtostore to install)")
	}

	// 5. Display summary
	block, _ := pem.Decode(rootPEM)
	if block != nil {
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr == nil {
			hash := sha256.Sum256(cert.Raw)
			fp := "SHA256:" + strings.ToUpper(hex.EncodeToString(hash[:]))
			fmt.Printf("Root CA Subject:     %s\n", cert.Subject.CommonName)
			fmt.Printf("Root CA Fingerprint: %s\n", fp)
			fmt.Printf("Not After:           %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	fmt.Printf("Root CA stored:      %s\n", rootPath)
	fmt.Println("Bootstrap complete.")
	return nil
}

// bootstrapFingerprintSubcommand returns the "fingerprint" subcommand.
func bootstrapFingerprintSubcommand() *cli.Command {
	return &cli.Command{
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
	}
}

// bootstrapTrustSubcommand returns the "trust" subcommand group.
func bootstrapTrustSubcommand() *cli.Command {
	return &cli.Command{
		Name:  "trust",
		Usage: "Trust management subcommands",
		Subcommands: []*cli.Command{
			{
				Name:  "install",
				Usage: "Install CA root trust (fetches and stores root, no platform trust store install)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "ca-url", Usage: "Step CA URL", Required: true},
					&cli.StringFlag{Name: "fingerprint", Usage: "Expected root fingerprint (auto TOFU if omitted)"},
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
	}
}

