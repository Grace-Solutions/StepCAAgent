// stepcaagent is a cross-platform certificate lifecycle agent for Step CA.
package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	app := &cli.App{
		Name:    "stepcaagent",
		Usage:   "Certificate lifecycle agent for Step CA",
		Version: Version,
		Metadata: map[string]interface{}{},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "path to config file",
				EnvVars: []string{"STEPCAAGENT_CONFIG"},
			},
			&cli.StringFlag{
				Name:    "config-url",
				Usage:   "URL to download config from (overrides --config)",
				EnvVars: []string{"STEPCAAGENT_CONFIG_URL"},
			},
			&cli.StringFlag{
				Name:    "config-header",
				Usage:   "HTTP header name for authenticated config download",
				EnvVars: []string{"STEPCAAGENT_CONFIG_HEADER"},
			},
			&cli.StringFlag{
				Name:    "config-token",
				Usage:   "HTTP header value/token for authenticated config download",
				EnvVars: []string{"STEPCAAGENT_CONFIG_TOKEN"},
			},
			&cli.StringFlag{
				Name:    "config-method",
				Usage:   "HTTP method for config-url: GET (default) or POST (webhook mode with device identifiers)",
				Value:   "GET",
				EnvVars: []string{"STEPCAAGENT_CONFIG_METHOD"},
			},
			&cli.StringFlag{
				Name:    "config-url-refresh-interval",
				Usage:   "How often to re-fetch config from --config-url (e.g. 8h, 30m). Default: 8h. Set to 0 to disable.",
				Value:   "8h",
				EnvVars: []string{"STEPCAAGENT_CONFIG_URL_REFRESH_INTERVAL"},
			},
		},
		Before: func(c *cli.Context) error {
			c.App.Metadata["configPath"] = c.String("config")
			c.App.Metadata["configURL"] = c.String("config-url")
			c.App.Metadata["configHeader"] = c.String("config-header")
			c.App.Metadata["configToken"] = c.String("config-token")
			c.App.Metadata["configMethod"] = c.String("config-method")
			c.App.Metadata["configURLRefreshInterval"] = c.String("config-url-refresh-interval")
			return nil
		},
		Commands: []*cli.Command{
			serviceCommand(),
			configCommand(),
			bootstrapCommand(),
			certCommand(),
			statusCommand(),
			doctorCommand(),
			runOnceCommand(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

