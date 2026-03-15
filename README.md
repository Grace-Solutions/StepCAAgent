# StepCAAgent

A cross-platform certificate lifecycle agent for [Smallstep Certificate Authority](https://smallstep.com/docs/step-ca/).
StepCAAgent automates certificate enrollment, renewal, trust-store management, and health monitoring — running as an OS service on Windows, Linux, and macOS.

## Features

- **Automated certificate lifecycle** — enrollment, renewal, and revocation via Step CA
- **Cross-platform** — Windows (amd64/arm64), Linux (amd64/arm64), macOS (amd64/arm64)
- **OS service integration** — runs as a Windows Service, systemd unit, or launchd daemon
- **Platform trust-store management** — installs root CA and leaf certificates into Windows Certificate Store, macOS Keychain, or Linux system trust
- **Auto-discovery** — detects hostname, DNS suffixes, IP addresses, serial number, and OS info
- **Webhook config** — fetch configuration dynamically from a webhook (e.g., n8n) with device-specific payloads
- **Domain filtering** — regex-based inclusion/exclusion of auto-discovered DNS domains
- **Wildcard SAN support** — optionally generate `*.suffix` SANs instead of host-specific FQDNs
- **WindowsPE support** — single-shot `run-once` mode for imaging and provisioning pipelines
- **Trust-On-First-Use (TOFU)** — automatic root CA fingerprint detection on first bootstrap

## Quickstart

### 1. Download the binary

Pre-built binaries are in the [`binaries/`](binaries/) directory:

| Platform | Binary |
|---|---|
| Windows x64 | `stepcaagent-windows-amd64.exe` |
| Windows ARM64 | `stepcaagent-windows-arm64.exe` |
| Linux x64 | `stepcaagent-linux-amd64` |
| Linux ARM64 | `stepcaagent-linux-arm64` |
| macOS x64 | `stepcaagent-darwin-amd64` |
| macOS Apple Silicon | `stepcaagent-darwin-arm64` |

### 2. Bootstrap the CA root

```bash
# Fetch and trust the CA root certificate (TOFU — auto-detects fingerprint)
stepcaagent bootstrap --ca-url https://ca.example.com:9100 --installtostore

# Or verify with a known fingerprint
stepcaagent bootstrap --ca-url https://ca.example.com:9100 \
  --fingerprint "SHA256:abc123..." --installtostore
```

### 3. Create a config file

Generate a sample config:

```bash
stepcaagent config sample --out config.json
```

Or create one manually (see [Configuration Reference](#configuration-reference) below).

### 4a. Run as a service (recommended)

```bash
# Install and start the OS service
stepcaagent service initialize --config /path/to/config.json

# Or install and start separately
stepcaagent service install --config /path/to/config.json
stepcaagent service start
```

### 4b. Run with a webhook config source

```bash
# Install service with remote config from a webhook
stepcaagent service initialize \
  --config-url "https://automation.example.com/webhook/StepCAAgent" \
  --config-header Authorization \
  --config-token "your-secret-token" \
  --config-method POST
```

### 4c. Single-shot mode (WindowsPE / CI)

```bash
stepcaagent run-once --config config.json
# or with webhook
stepcaagent run-once \
  --config-url "https://automation.example.com/webhook/StepCAAgent" \
  --config-header Authorization --config-token "your-token" \
  --config-method POST
```

## CLI Reference

### Global Flags

| Flag | Env Var | Description |
|---|---|---|
| `--config`, `-c` | `STEPCAAGENT_CONFIG` | Path to local config file |
| `--config-url` | `STEPCAAGENT_CONFIG_URL` | URL to download config from (overrides `--config`) |
| `--config-header` | `STEPCAAGENT_CONFIG_HEADER` | HTTP header name for authenticated config download |
| `--config-token` | `STEPCAAGENT_CONFIG_TOKEN` | HTTP header value/token for authenticated config download |
| `--config-method` | `STEPCAAGENT_CONFIG_METHOD` | HTTP method: `GET` (default) or `POST` (webhook mode) |
| `--config-url-refresh-interval` | `STEPCAAGENT_CONFIG_URL_REFRESH_INTERVAL` | How often to re-fetch remote config (default: `8h`, `0` to disable) |

### Commands

```
stepcaagent service install       Register as OS service (idempotent)
stepcaagent service uninstall     Stop + remove service (idempotent)
stepcaagent service start         Start the registered service
stepcaagent service stop          Stop the running service
stepcaagent service initialize    Install + start in one step
stepcaagent service run           Run in foreground (debug mode)

stepcaagent config sample         Generate a sample config file
stepcaagent config validate       Validate a config file

stepcaagent bootstrap             Fetch CA root cert (TOFU or fingerprint)
stepcaagent bootstrap fingerprint Fetch and display CA root fingerprint
stepcaagent bootstrap trust install   Install CA root trust
stepcaagent bootstrap trust refresh   Refresh CA root trust

stepcaagent cert request          Request a new certificate
stepcaagent cert renew            Renew a certificate (--name or --all)
stepcaagent cert list             List managed certificates
stepcaagent cert inspect          Inspect a managed certificate

stepcaagent status                Show agent status
stepcaagent doctor                Run diagnostic checks
stepcaagent run-once              Single reconciliation cycle and exit
```

## Configuration Reference

### Minimal Config

```json
{
  "Settings": {
    "logLevel": "info",
    "bootstrap": {
      "caUrl": "https://ca.example.com:9100"
    },
    "trust": {
      "installRoots": true,
      "refreshInterval": "24h"
    }
  },
  "Provisioners": [
    {
      "provisionerName": "my-cert",
      "enabled": true,
      "installToStore": true,
      "store": "localmachine",
      "subject": {
        "commonName": "auto",
        "dnsNames": ["auto"],
        "ipAddresses": ["auto"]
      },
      "auth": {
        "type": "provisioner-password",
        "password": "your-provisioner-password"
      }
    }
  ]
}
```

### Settings

| Field | Type | Default | Description |
|---|---|---|---|
| `logLevel` | string | `"info"` | Log level: `debug`, `info`, `warn`, `error` |
| `logMaxFiles` | int | `3` | Number of daily log files to retain |
| `pollInterval` | string | `"15m"` | How often to check certificates |
| `baseDirectory` | string | `"<binary>/data"` | Root directory for all data |
| `domains` | object | | Regex-based domain filter (see below) |
| `bootstrap.caUrl` | string | *required* | Step CA server URL |
| `bootstrap.fingerprint` | string | auto (TOFU) | Root CA fingerprint for verification |
| `trust.installRoots` | bool | `false` | Install root CA into platform trust store |
| `trust.refreshInterval` | string | `"24h"` | How often to check root CA validity |

### Domain Filtering

The `domains` object controls which auto-discovered DNS suffixes are included in certificate SANs.
Both patterns are case-insensitive Go regular expressions.

| Field | Default | Description |
|---|---|---|
| `domains.inclusionExpression` | `".*"` | Regex pattern — only matching suffixes are included |
| `domains.exclusionExpression` | `"^$"` | Regex pattern — matching suffixes are excluded (applied after inclusion) |

**Example:** Include only `.ts.net` and `.example.com` domains, exclude anything with `test`:

```json
"domains": {
  "inclusionExpression": "\\.(ts\\.net|example\\.com)$",
  "exclusionExpression": "(?i)test"
}
```

### Provisioner Settings

| Field | Type | Default | Description |
|---|---|---|---|
| `provisionerName` | string | *required* | CA provisioner name (also used as local cert identifier) |
| `enabled` | bool | `false` | Whether this provisioner is active |
| `installToStore` | bool | `false` | Import certificate into platform certificate store |
| `store` | string | `"localmachine"` | Store scope: `localmachine`, `currentuser`, `both`, or `auto` |
| `friendlyName` | string | `"auto"` | Display name in cert store; `"auto"` uses provisionerName |
| `wildcard` | bool | `false` | Generate `*.suffix` SANs for each discovered DNS suffix |
| `subject.commonName` | string | | CN for the cert; `"auto"` = hostname |
| `subject.dnsNames` | []string | | DNS SANs; `["auto"]` = auto-discovered FQDNs |
| `subject.ipAddresses` | []string | | IP SANs; `["auto"]` = auto-discovered IPs |
| `key.algorithm` | string | `"EC"` | Key algorithm: `EC` or `RSA` |
| `key.curve` | string | `"P256"` | EC curve: `P256`, `P384` |
| `key.rsaBits` | int | `2048` | RSA key size (only when algorithm is `RSA`) |
| `auth.type` | string | *required* | Auth type: `provisioner-password`, `jwk`, `bootstrap-token`, `acme` |
| `auth.password` | string | | Provisioner password (for `provisioner-password` type) |

## Webhook Config Mode

When using `--config-url` with `--config-method POST`, the agent sends a JSON payload to the webhook containing device identity:

```json
{
  "cn": "myhostname",
  "sans": ["myhostname", "myhostname.example.com", "myhostname.ts.net"],
  "ips": ["10.0.0.5", "100.64.0.1"],
  "serial": "ABC123",
  "osType": "Workstation",
  "osVersion": "10.0.26100"
}
```

The webhook should return a full config JSON. The agent applies it immediately (held in memory, never written to disk unless `--config` is also specified).

Config is automatically refreshed on a jittered interval (default `8h`, configurable via `--config-url-refresh-interval`). Each refresh cycle applies ±15% random jitter to prevent thundering herd.

## Logging

- Log files are written to `<binary>/data/logs/stepcaagent.YYYY.MM.DD.log`
- Maximum 10 MB per log file
- Only the last 3 daily log files are retained (configurable via `logMaxFiles`)
- In service mode, logs go to file only; in `service run` (foreground) mode, logs also go to stderr

## Building from Source

```bash
cd src
go build -o stepcaagent ./cmd/stepcaagent
```

Cross-compile for all platforms:

```bash
# Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o stepcaagent-linux-amd64 ./cmd/stepcaagent
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o stepcaagent-linux-arm64 ./cmd/stepcaagent

# macOS
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o stepcaagent-darwin-amd64 ./cmd/stepcaagent
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o stepcaagent-darwin-arm64 ./cmd/stepcaagent

# Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o stepcaagent-windows-amd64.exe ./cmd/stepcaagent
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o stepcaagent-windows-arm64.exe ./cmd/stepcaagent
```

## License

Copyright © Grace Solutions. All rights reserved.