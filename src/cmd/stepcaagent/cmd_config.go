package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/GraceSolutions/StepCAAgent/internal/config"
)

func configCommand() *cli.Command {
	return &cli.Command{
		Name:  "config",
		Usage: "Configuration management",
		Subcommands: []*cli.Command{
			{
				Name:  "sample",
				Usage: "Generate a sample config file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "out",
						Aliases: []string{"o"},
						Usage:   "output file path (stdout if omitted)",
					},
				},
				Action: func(c *cli.Context) error {
					data, err := config.GenerateSample()
					if err != nil {
						return fmt.Errorf("generate sample: %w", err)
					}
					out := c.String("out")
					if out == "" {
						fmt.Println(string(data))
						return nil
					}
					if err := os.WriteFile(out, data, 0600); err != nil {
						return fmt.Errorf("write %s: %w", out, err)
					}
					fmt.Printf("Sample config written to %s\n", out)
					return nil
				},
			},
			{
				Name:  "validate",
				Usage: "Validate a config file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "config file to validate",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					cfg, err := config.LoadFromFile(c.String("file"))
					if err != nil {
						return err
					}
					fmt.Printf("Config is valid. %d provisioner(s) defined.\n", len(cfg.Provisioners))
					return nil
				},
			},
			{
				Name:  "test-source",
				Usage: "Test a remote config source URL",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "url",
						Usage:    "URL to test",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					// TODO: implement remote config source testing
					fmt.Println("Remote config source testing not yet implemented.")
					return nil
				},
			},
		},
	}
}

