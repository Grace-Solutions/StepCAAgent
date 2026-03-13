package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/kardianos/service"
	"github.com/urfave/cli/v2"

	"github.com/GraceSolutions/StepCAAgent/internal/ca"
	"github.com/GraceSolutions/StepCAAgent/internal/certstore"
	"github.com/GraceSolutions/StepCAAgent/internal/config"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/state"
)

const maxRetries = 10 // After this many consecutive failures, halt until service restart

// agentService implements kardianos/service.Interface.
type agentService struct {
	configPath   string
	configURL    string
	configHeader string
	configToken  string
	cancel       context.CancelFunc
}

func (a *agentService) Start(s service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go a.run(ctx)
	return nil
}

func (a *agentService) run(ctx context.Context) {
	log := logging.Logger()
	log.Info("agent service started")

	// 1. Load config (from URL or file)
	var cfg *config.Root
	var err error

	if a.configURL != "" {
		log.Info("loading configuration from URL", "url", a.configURL)
		cfg, err = config.LoadFromURL(a.configURL, a.configHeader, a.configToken, a.configPath)
	} else {
		cfgPath := a.configPath
		if cfgPath == "" {
			exe, exeErr := os.Executable()
			if exeErr != nil {
				log.Error("could not determine executable path", "error", exeErr)
				return
			}
			cfgPath = filepath.Join(filepath.Dir(exe), "stepcaagent.json")
		}
		log.Info("loading configuration", "path", cfgPath)
		cfg, err = config.LoadFromFile(cfgPath)
	}
	if err != nil {
		log.Error("failed to load configuration", "error", err)
		return
	}
	log.Info("configuration loaded successfully", "provisioners", len(cfg.Provisioners))

	// 3. Initialize logging from config
	if err := logging.Init(logging.Config{
		Directory: cfg.Settings.LogDirectory(),
		Level:     cfg.Settings.LogLevel,
		MaxFiles:  cfg.Settings.LogMaxFiles,
	}); err != nil {
		log.Error("failed to reinitialize logging from config", "error", err)
	}
	log = logging.Logger()

	// 4. Open state database
	log.Info("opening state database", "directory", cfg.Settings.StateDirectory())
	db, err := state.Open(cfg.Settings.StateDirectory())
	if err != nil {
		log.Error("failed to open state database", "error", err)
		return
	}
	defer db.Close()
	log.Info("state database opened", "path", db.Path())

	// 5. Bootstrap CA trust
	log.Info("bootstrapping CA trust", "caUrl", cfg.Settings.Bootstrap.CAUrl)
	caClient, err := ca.NewClient(cfg.Settings.Bootstrap.CAUrl, cfg.Settings.CertificatesDirectory(), cfg.Settings.Bootstrap.Fingerprint)
	if err != nil {
		log.Error("failed to create CA client", "error", err)
		return
	}

	if err := caClient.RefreshRoot(30 * 24 * time.Hour); err != nil {
		log.Error("failed to bootstrap/refresh CA root trust", "error", err)
		// Continue — may already have a valid root
	} else {
		log.Info("CA root trust established")
	}
	_ = db.UpdateCAStatus(true, "")

	// 6. Parse poll interval
	pollInterval := 15 * time.Minute
	if d, err := time.ParseDuration(cfg.Settings.PollInterval); err == nil {
		pollInterval = d
	}
	log.Info("entering main reconciliation loop", "pollInterval", pollInterval)

	// 7. Run initial reconciliation immediately, then on timer
	a.reconcile(cfg, caClient, db)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("service context cancelled, exiting loop")
			return
		case <-ticker.C:
			a.reconcile(cfg, caClient, db)
		}
	}
}

// reconcile processes all provisioners: enroll new certs, renew expiring ones.
// It uses smart scheduling: after a successful enrollment/renewal, the next check
// time is calculated from the certificate's actual lifetime and stored in the DB.
// Provisioners are skipped until their next_scheduled time arrives.
// After maxRetries consecutive failures, a provisioner is halted until service restart.
func (a *agentService) reconcile(cfg *config.Root, caClient *ca.Client, db *state.DB) {
	log := logging.Logger()
	log.Info("starting reconciliation cycle", "provisioners", len(cfg.Provisioners))

	// Build set of active provisioner names for stale cert detection
	activeNames := make(map[string]bool)
	for _, prov := range cfg.Provisioners {
		activeNames[prov.Name] = true
	}

	// Clean up certs for provisioners no longer in config
	a.cleanupStaleCerts(cfg, caClient, db, activeNames)

	for _, prov := range cfg.Provisioners {
		if !prov.Enabled {
			log.Info("provisioner disabled, skipping", "name", prov.Name)
			continue
		}

		// Check retry count — halt after maxRetries until service restart
		retryCount, _ := db.GetRetryCount(prov.Name)
		if retryCount >= maxRetries {
			log.Error("provisioner halted after max retries, restart service to retry",
				"provisioner", prov.Name,
				"retryCount", retryCount,
				"maxRetries", maxRetries)
			continue
		}

		// Check if this provisioner is due for processing
		nextScheduled, err := db.GetNextScheduled(prov.Name)
		if err != nil {
			log.Error("error reading next_scheduled", "provisioner", prov.Name, "error", err)
		}
		if !nextScheduled.IsZero() && time.Now().Before(nextScheduled) {
			log.Info("provisioner not due yet, skipping",
				"provisioner", prov.Name,
				"nextScheduled", nextScheduled.UTC(),
				"remaining", time.Until(nextScheduled))
			continue
		}

		log.Info("processing provisioner", "name", prov.Name)

		needs, renewAt, err := ca.NeedsRenewal(cfg.Settings.CertificatesDirectory(), prov)
		if err != nil {
			log.Error("error checking renewal status", "provisioner", prov.Name, "error", err)
			needs = true
		}

		if !needs {
			log.Info("certificate is current, no action needed",
				"provisioner", prov.Name,
				"nextRenewalAt", renewAt.UTC())
			_ = db.UpdateRenewalTracking(prov.Name, true, renewAt, "")
			continue
		}

		// Try renewal first (if cert exists), fall back to enrollment
		log.Info("certificate needs renewal/enrollment", "provisioner", prov.Name)

		err = caClient.RenewCertificate(prov, db)
		if err != nil {
			log.Warn("renewal failed, attempting fresh enrollment", "provisioner", prov.Name, "error", err)
			if enrollErr := caClient.EnrollCertificate(prov, db); enrollErr != nil {
				// Calculate backoff with jitter
				backoff := calculateBackoff(prov.Renewal.Backoff, retryCount)
				nextRetry := time.Now().Add(backoff)
				log.Error("enrollment also failed, scheduling retry with backoff",
					"provisioner", prov.Name,
					"error", enrollErr,
					"retryCount", retryCount+1,
					"backoff", backoff,
					"nextRetry", nextRetry.UTC())
				_ = db.UpdateRenewalTracking(prov.Name, false, nextRetry, enrollErr.Error())
				continue
			}
		}

		// After successful enrollment/renewal, compute next renewal time from the new cert
		_, nextRenewAt, calcErr := ca.NeedsRenewal(cfg.Settings.CertificatesDirectory(), prov)
		if calcErr != nil {
			nextRenewAt = time.Now().Add(time.Hour)
		}

		log.Info("provisioner certificate updated successfully",
			"provisioner", prov.Name,
			"nextRenewalAt", nextRenewAt.UTC(),
			"sleepUntil", time.Until(nextRenewAt))
		_ = db.UpdateRenewalTracking(prov.Name, true, nextRenewAt, "")
	}

	log.Info("reconciliation cycle complete")
}

// calculateBackoff computes exponential backoff with jitter.
// Formula: min(max, initial * 2^retryCount) + random jitter up to 25%.
func calculateBackoff(backoffCfg config.Backoff, retryCount int) time.Duration {
	initial := time.Minute
	if d, err := time.ParseDuration(backoffCfg.Initial); err == nil {
		initial = d
	}
	maxBackoff := time.Hour
	if d, err := time.ParseDuration(backoffCfg.Max); err == nil {
		maxBackoff = d
	}

	backoff := float64(initial) * math.Pow(2, float64(retryCount))
	if backoff > float64(maxBackoff) {
		backoff = float64(maxBackoff)
	}

	// Add jitter: 0-25% of the backoff
	jitter := backoff * 0.25 * rand.Float64()
	return time.Duration(backoff + jitter)
}

// cleanupStaleCerts revokes and removes certificates for provisioners
// that are no longer present in the configuration.
func (a *agentService) cleanupStaleCerts(cfg *config.Root, caClient *ca.Client, db *state.DB, activeNames map[string]bool) {
	log := logging.Logger()

	trackedNames, err := db.ListTrackedCertNames()
	if err != nil {
		log.Error("could not list tracked certs for cleanup", "error", err)
		return
	}

	for _, name := range trackedNames {
		if activeNames[name] {
			continue
		}

		log.Warn("provisioner no longer in config, revoking and removing", "provisioner", name)

		// Try to revoke via CA
		certRec, err := db.GetCertificate(name)
		if err == nil && certRec != nil {
			log.Info("revoking certificate", "provisioner", name, "serial", certRec.Serial)
			if err := caClient.RevokeCertificate(certRec.Serial, certRec.StoragePath); err != nil {
				log.Error("revocation failed, continuing with removal",
					"provisioner", name, "error", err)
			} else {
				log.Info("certificate revoked successfully", "provisioner", name)
			}
			_ = db.RecordAuditEvent("revoked", name, "provisioner removed from config", "success")
		}

		// Remove cert and key files
		paths := certstore.ResolvePaths(cfg.Settings.CertificatesDirectory(), name)
		for _, f := range []string{paths.Certificate, paths.PrivateKey, paths.Chain} {
			if f != "" {
				if rmErr := os.Remove(f); rmErr != nil && !os.IsNotExist(rmErr) {
					log.Warn("could not remove file", "path", f, "error", rmErr)
				} else {
					log.Info("removed file", "path", f)
				}
			}
		}

		// Remove from state DB
		if err := db.DeleteCertificate(name); err != nil {
			log.Error("could not delete certificate record", "provisioner", name, "error", err)
		}
		if err := db.DeleteRenewalTracking(name); err != nil {
			log.Error("could not delete renewal tracking", "provisioner", name, "error", err)
		}

		log.Info("stale provisioner cleaned up", "provisioner", name)
	}
}

func (a *agentService) Stop(s service.Service) error {
	log := logging.Logger()
	log.Info("agent service stopping")
	if a.cancel != nil {
		a.cancel()
	}
	return nil
}

func newServiceConfig() *service.Config {
	return &service.Config{
		Name:        config.ServiceName,
		DisplayName: "Step CA Agent",
		Description: "Certificate lifecycle agent for Step CA environments",
	}
}

func serviceCommand() *cli.Command {
	return &cli.Command{
		Name:  "service",
		Usage: "Manage the OS service",
		Subcommands: []*cli.Command{
			{
				Name:  "install",
				Usage: "Register as OS service (idempotent)",
				Action: func(c *cli.Context) error {
					return serviceInstall()
				},
			},
			{
				Name:  "uninstall",
				Usage: "Stop (if running) + remove service (idempotent)",
				Action: func(c *cli.Context) error {
					return serviceUninstall()
				},
			},
			{
				Name:  "start",
				Usage: "Start the registered service",
				Action: func(c *cli.Context) error {
					return serviceStart()
				},
			},
			{
				Name:  "stop",
				Usage: "Stop the running service",
				Action: func(c *cli.Context) error {
					return serviceStop()
				},
			},
			{
				Name:  "initialize",
				Usage: "Install + start in one step",
				Action: func(c *cli.Context) error {
					if err := serviceInstall(); err != nil {
						return err
					}
					return serviceStart()
				},
			},
			{
				Name:  "run",
				Usage: "Run in foreground (debug mode)",
				Action: func(c *cli.Context) error {
					return serviceRun(c.String("config"))
				},
			},
		},
	}
}

func getService(configPath ...string) (service.Service, error) {
	svc := &agentService{}
	if len(configPath) > 0 {
		svc.configPath = configPath[0]
	}
	return service.New(svc, newServiceConfig())
}

func serviceInstall() error {
	s, err := getService()
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	// Idempotent: check if already installed by trying status.
	status, err := s.Status()
	if err == nil {
		fmt.Printf("Service already installed (status: %v)\n", statusString(status))
		return nil
	}
	if err := s.Install(); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	fmt.Println("Service installed successfully.")
	return nil
}

func serviceUninstall() error {
	s, err := getService()
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	// Idempotent: stop if running, then uninstall. Ignore errors for "not installed".
	status, statusErr := s.Status()
	if statusErr != nil {
		// Not installed — nothing to do.
		fmt.Println("Service is not installed.")
		return nil
	}
	if status == service.StatusRunning {
		fmt.Println("Stopping service...")
		if err := s.Stop(); err != nil {
			fmt.Printf("Warning: could not stop service: %v\n", err)
		}
	}
	if err := s.Uninstall(); err != nil {
		return fmt.Errorf("uninstall service: %w", err)
	}
	fmt.Println("Service uninstalled successfully.")
	return nil
}

func serviceStart() error {
	s, err := getService()
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Println("Service started.")
	return nil
}

func serviceStop() error {
	s, err := getService()
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	if err := s.Stop(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	fmt.Println("Service stopped.")
	return nil
}

func serviceRun(configPath string) error {
	// Initialize logging for foreground mode (also write to stderr).
	if err := logging.Init(logging.Config{ToStderr: true, Level: "debug"}); err != nil {
		return fmt.Errorf("init logging: %w", err)
	}
	defer logging.Close()

	s, err := getService(configPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	return s.Run()
}

func statusString(s service.Status) string {
	switch s {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

