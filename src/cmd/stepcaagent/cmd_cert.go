package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/GraceSolutions/StepCAAgent/internal/ca"
	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
	"github.com/GraceSolutions/StepCAAgent/internal/config"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/state"
)

func certCommand() *cli.Command {
	return &cli.Command{
		Name:  "cert",
		Usage: "Certificate operations",
		Subcommands: []*cli.Command{
			{
				Name:  "request",
				Usage: "Request a new certificate",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Provisioner name", Required: true},
					&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "Config file path"},
				},
				Action: certRequestAction,
			},
			{
				Name:  "renew",
				Usage: "Renew a certificate",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Provisioner name"},
					&cli.BoolFlag{Name: "all", Usage: "Renew all certificates"},
					&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "Config file path"},
				},
				Action: certRenewAction,
			},
			{
				Name:  "list",
				Usage: "List managed certificates",
				Action: certListAction,
			},
			{
				Name:  "inspect",
				Usage: "Inspect a managed certificate",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Provisioner name", Required: true},
					&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "Config file path"},
				},
				Action: certInspectAction,
			},
		},
	}
}

func loadConfigForCLI(c *cli.Context) (*config.Root, error) {
	cfgPath := resolveConfigPath(c)
	if cfgPath == "" {
		return nil, fmt.Errorf("--config flag or STEPCAAGENT_CONFIG is required")
	}
	return config.LoadFromFile(cfgPath)
}

func resolveConfigPath(c *cli.Context) string {
	// Check local --config flag first, then global
	if p := c.String("config"); p != "" {
		return p
	}
	if c.App != nil && c.App.Metadata != nil {
		if md, ok := c.App.Metadata["configPath"]; ok {
			if s, ok := md.(string); ok {
				return s
			}
		}
	}
	return ""
}

func findProvisioner(cfg *config.Root, name string) (*config.Provisioner, error) {
	for i := range cfg.Provisioners {
		if cfg.Provisioners[i].ProvisionerName == name {
			return &cfg.Provisioners[i], nil
		}
	}
	return nil, fmt.Errorf("provisioner %q not found in config", name)
}

func certRequestAction(c *cli.Context) error {
	if err := logging.Init(logging.Config{ToStderr: true, Level: "info"}); err != nil {
		return err
	}
	defer logging.Close()

	cfg, err := loadConfigForCLI(c)
	if err != nil {
		return err
	}

	prov, err := findProvisioner(cfg, c.String("name"))
	if err != nil {
		return err
	}

	db, err := state.Open(cfg.Settings.StateDirectory())
	if err != nil {
		return fmt.Errorf("open state db: %w", err)
	}
	defer db.Close()

	client, err := ca.NewClient(cfg.Settings.Bootstrap.CAUrl, cfg.Settings.CertificatesDirectory(), cfg.Settings.Bootstrap.Fingerprint)
	if err != nil {
		return fmt.Errorf("create CA client: %w", err)
	}

	if err := client.EnrollCertificate(*prov, db); err != nil {
		return fmt.Errorf("enroll certificate: %w", err)
	}

	fmt.Printf("Certificate enrolled successfully for provisioner %q.\n", prov.ProvisionerName)
	return nil
}

func certRenewAction(c *cli.Context) error {
	if err := logging.Init(logging.Config{ToStderr: true, Level: "info"}); err != nil {
		return err
	}
	defer logging.Close()

	cfg, err := loadConfigForCLI(c)
	if err != nil {
		return err
	}

	db, err := state.Open(cfg.Settings.StateDirectory())
	if err != nil {
		return fmt.Errorf("open state db: %w", err)
	}
	defer db.Close()

	client, err := ca.NewClient(cfg.Settings.Bootstrap.CAUrl, cfg.Settings.CertificatesDirectory(), cfg.Settings.Bootstrap.Fingerprint)
	if err != nil {
		return fmt.Errorf("create CA client: %w", err)
	}

	if c.Bool("all") {
		for _, prov := range cfg.Provisioners {
			if !prov.Enabled {
				continue
			}
			fmt.Printf("Renewing %q...\n", prov.ProvisionerName)
			if err := client.RenewCertificate(prov, db); err != nil {
				fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
			} else {
				fmt.Printf("  Renewed successfully.\n")
			}
		}
		return nil
	}

	name := c.String("name")
	if name == "" {
		return fmt.Errorf("--name or --all is required")
	}

	prov, err := findProvisioner(cfg, name)
	if err != nil {
		return err
	}

	if err := client.RenewCertificate(*prov, db); err != nil {
		return fmt.Errorf("renew certificate: %w", err)
	}

	fmt.Printf("Certificate renewed successfully for provisioner %q.\n", prov.ProvisionerName)
	return nil
}

func certListAction(c *cli.Context) error {
	if err := logging.Init(logging.Config{ToStderr: true, Level: "warn"}); err != nil {
		return err
	}
	defer logging.Close()

	db, err := state.Open("")
	if err != nil {
		return fmt.Errorf("open state db: %w", err)
	}
	defer db.Close()

	certs, err := db.ListCertificates()
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}

	if len(certs) == 0 {
		fmt.Println("No managed certificates found.")
		return nil
	}

	fmt.Printf("%-20s %-30s %-25s %-25s\n", "NAME", "SUBJECT", "NOT AFTER", "STORAGE")
	for _, cert := range certs {
		fmt.Printf("%-20s %-30s %-25s %-25s\n",
			cert.Name,
			cert.Subject,
			cert.NotAfter.UTC().Format(time.RFC3339),
			cert.StoragePath)
	}
	return nil
}

func certInspectAction(c *cli.Context) error {
	if err := logging.Init(logging.Config{ToStderr: true, Level: "warn"}); err != nil {
		return err
	}
	defer logging.Close()

	cfg, err := loadConfigForCLI(c)
	if err != nil {
		return err
	}

	prov, err := findProvisioner(cfg, c.String("name"))
	if err != nil {
		return err
	}

	paths := certstore.ResolvePaths(cfg.Settings.CertificatesDirectory(), prov.ProvisionerName)

	certData, err := os.ReadFile(paths.Certificate)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("no PEM block in certificate file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	fmt.Printf("Provisioner:  %s\n", prov.ProvisionerName)
	fmt.Printf("Subject:      %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer:       %s\n", cert.Issuer.CommonName)
	fmt.Printf("Serial:       %s\n", cert.SerialNumber.String())
	fmt.Printf("Not Before:   %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
	fmt.Printf("Not After:    %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("DNS Names:    %v\n", cert.DNSNames)
	fmt.Printf("IP Addresses: %v\n", cert.IPAddresses)
	fmt.Printf("Cert Path:    %s\n", paths.Certificate)
	fmt.Printf("Key Path:     %s\n", paths.PrivateKey)
	return nil
}

