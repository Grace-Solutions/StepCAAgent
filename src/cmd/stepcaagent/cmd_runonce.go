package main

import (
	"fmt"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/GraceSolutions/StepCAAgent/internal/ca"
	"github.com/GraceSolutions/StepCAAgent/internal/config"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/state"
)

// runOnceCommand returns the "run-once" CLI command for single-execution mode.
// This is intended for WindowsPE or other environments where the agent should
// process all provisioners once and then exit.
func runOnceCommand() *cli.Command {
	return &cli.Command{
		Name:  "run-once",
		Usage: "Run a single reconciliation cycle and exit (for WindowsPE / ephemeral environments)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "Config file path"},
			&cli.StringFlag{Name: "config-url", Usage: "URL to download config from"},
			&cli.StringFlag{Name: "config-header", Usage: "HTTP header name for auth"},
			&cli.StringFlag{Name: "config-token", Usage: "HTTP header value for auth"},
			&cli.StringFlag{Name: "config-method", Usage: "HTTP method: GET (default) or POST (webhook)", Value: "GET"},
		},
		Action: runOnceAction,
	}
}

func runOnceAction(c *cli.Context) error {
	if err := logging.Init(logging.Config{ToStderr: true, Level: "info"}); err != nil {
		return fmt.Errorf("init logging: %w", err)
	}
	defer logging.Close()
	log := logging.Logger()

	// Load config from URL or file
	cfg, err := loadConfigFromContext(c)
	if err != nil {
		return err
	}

	log.Info("run-once mode: loaded configuration", "provisioners", len(cfg.Provisioners))

	// Open state database
	db, err := state.Open(cfg.Settings.StateDirectory())
	if err != nil {
		return fmt.Errorf("open state db: %w", err)
	}
	defer db.Close()

	// Bootstrap CA trust
	caClient, err := ca.NewClient(cfg.Settings.Bootstrap.CAUrl, cfg.Settings.CertificatesDirectory(), cfg.Settings.Bootstrap.Fingerprint)
	if err != nil {
		return fmt.Errorf("create CA client: %w", err)
	}

	if err := caClient.RefreshRoot(30 * 24 * time.Hour); err != nil {
		log.Warn("CA root trust refresh failed, continuing", "error", err)
	}
	_ = db.UpdateCAStatus(true, "")

	// Run single reconciliation
	svc := &agentService{}
	svc.reconcile(cfg, caClient, db)

	log.Info("run-once mode: reconciliation complete, exiting")
	return nil
}

// loadConfigFromContext loads config from URL or file based on CLI context.
func loadConfigFromContext(c *cli.Context) (*config.Root, error) {
	// Check for URL-based config (from local flag or global metadata)
	configURL := c.String("config-url")
	if configURL == "" {
		if c.App != nil && c.App.Metadata != nil {
			if v, ok := c.App.Metadata["configURL"].(string); ok {
				configURL = v
			}
		}
	}

	if configURL != "" {
		header := c.String("config-header")
		token := c.String("config-token")
		method := c.String("config-method")
		if header == "" {
			if v, ok := c.App.Metadata["configHeader"].(string); ok {
				header = v
			}
		}
		if token == "" {
			if v, ok := c.App.Metadata["configToken"].(string); ok {
				token = v
			}
		}
		if method == "" {
			if v, ok := c.App.Metadata["configMethod"].(string); ok {
				method = v
			}
		}

		destPath := c.String("config")
		return config.LoadFromURL(configURL, method, header, token, destPath)
	}

	// Fall back to file-based config
	cfgPath := resolveConfigPath(c)
	if cfgPath == "" {
		return nil, fmt.Errorf("either --config or --config-url is required")
	}
	return config.LoadFromFile(cfgPath)
}

