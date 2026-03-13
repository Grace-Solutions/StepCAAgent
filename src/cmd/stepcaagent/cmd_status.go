package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/state"
)

func statusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Show agent status",
		Action: func(c *cli.Context) error {
			if err := logging.Init(logging.Config{ToStderr: true, Level: "warn"}); err != nil {
				return err
			}
			defer logging.Close()

			db, err := state.Open("")
			if err != nil {
				fmt.Println("State DB: NOT AVAILABLE")
				return nil
			}
			defer db.Close()

			fmt.Println("=== StepCA Agent Status ===")
			fmt.Printf("State DB: %s\n", db.Path())

			// CA status
			reachable, lastCheck, lastErr, err := db.GetCAStatus()
			if err == nil {
				status := "unreachable"
				if reachable {
					status = "reachable"
				}
				fmt.Printf("CA Status: %s (last check: %s)\n", status, lastCheck)
				if lastErr != "" {
					fmt.Printf("CA Last Error: %s\n", lastErr)
				}
			}

			// Config state
			hash, ver, err := db.GetConfigState()
			if err == nil {
				fmt.Printf("Config: version=%d hash=%s\n", ver, hash)
			}

			// Certificates
			certs, err := db.ListCertificates()
			if err == nil {
				fmt.Printf("Managed Certificates: %d\n", len(certs))
				for _, cert := range certs {
					remaining := time.Until(cert.NotAfter)
					fmt.Printf("  - %s: expires %s (in %s)\n",
						cert.Name,
						cert.NotAfter.UTC().Format(time.RFC3339),
						remaining.Round(time.Hour))
				}
			}

			// Recent audit events
			events, err := db.RecentAuditEvents(5)
			if err == nil && len(events) > 0 {
				fmt.Println("Recent Events:")
				for _, e := range events {
					fmt.Printf("  [%s] %s %s: %s (%s)\n",
						e.Timestamp, e.EventType, e.CertName, e.Detail, e.Result)
				}
			}

			return nil
		},
	}
}

func doctorCommand() *cli.Command {
	return &cli.Command{
		Name:  "doctor",
		Usage: "Run diagnostic checks",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "Config file path"},
			&cli.StringFlag{Name: "ca-url", Usage: "Step CA URL to check connectivity"},
		},
		Action: func(c *cli.Context) error {
			if err := logging.Init(logging.Config{ToStderr: true, Level: "warn"}); err != nil {
				return err
			}
			defer logging.Close()

			fmt.Println("=== StepCA Agent Doctor ===")
			allOK := true

			// Check state DB
			db, err := state.Open("")
			if err != nil {
				fmt.Printf("[FAIL] State DB: %v\n", err)
				allOK = false
			} else {
				fmt.Printf("[OK]   State DB: %s\n", db.Path())
				db.Close()
			}

			// Check CA connectivity
			caURL := c.String("ca-url")
			if caURL != "" {
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Get(caURL + "/health")
				if err != nil {
					fmt.Printf("[FAIL] CA connectivity: %v\n", err)
					allOK = false
				} else {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						fmt.Printf("[OK]   CA connectivity: %s (HTTP %d)\n", caURL, resp.StatusCode)
					} else {
						fmt.Printf("[WARN] CA connectivity: %s (HTTP %d)\n", caURL, resp.StatusCode)
					}
				}
			} else {
				fmt.Println("[SKIP] CA connectivity: no --ca-url provided")
			}

			// Check config
			cfgPath := c.String("config")
			if cfgPath != "" {
				_, err := loadConfigForCLI(c)
				if err != nil {
					fmt.Printf("[FAIL] Config: %v\n", err)
					allOK = false
				} else {
					fmt.Printf("[OK]   Config: %s\n", cfgPath)
				}
			} else {
				fmt.Println("[SKIP] Config: no --config provided")
			}

			if allOK {
				fmt.Println("\nAll checks passed.")
			} else {
				fmt.Println("\nSome checks failed. See above for details.")
			}
			return nil
		},
	}
}

