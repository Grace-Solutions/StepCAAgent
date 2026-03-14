package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/permissions"
	"github.com/GraceSolutions/StepCAAgent/internal/vars"
)

// LoadFromFile reads, permission-checks, and parses the JSON config at path.
func LoadFromFile(path string) (*Root, error) {
	log := logging.Logger()

	// Verify restrictive permissions before reading.
	if err := permissions.VerifyRestrictive(path); err != nil {
		log.Warn("config file has insecure permissions", "path", path, "error", err)
		// Continue with a warning; callers may choose to abort.
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Root
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := cfg.applyDefaults(); err != nil {
		return nil, fmt.Errorf("config: defaults: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}

	// Resolve variables and "auto" keywords.
	if err := cfg.ResolveVariables(); err != nil {
		log.Warn("config: variable resolution had issues", "error", err)
		// Non-fatal: continue with partially resolved config
	}

	log.Info("config loaded", "path", path, "provisioners", len(cfg.Provisioners))
	return &cfg, nil
}

// ResolveVariables expands variable placeholders and "auto" keywords
// in all provisioner Subject fields.
func (r *Root) ResolveVariables() error {
	log := logging.Logger()
	log.Info("resolving config variables and auto-SANs")

	ctx, err := vars.NewContext()
	if err != nil {
		return fmt.Errorf("build variable context: %w", err)
	}

	for i := range r.Provisioners {
		p := &r.Provisioners[i]
		log.Info("resolving variables for provisioner", "name", p.Name)

		// CommonName
		p.Subject.CommonName = ctx.ResolveCommonName(p.Subject.CommonName)

		// DNS names
		p.Subject.DNSNames = ctx.ResolveDNSNames(p.Subject.DNSNames)

		// IP addresses
		p.Subject.IPAddresses = ctx.ResolveIPAddresses(p.Subject.IPAddresses)

		// URIs and emails - just variable expansion, no auto
		for j, u := range p.Subject.URIs {
			p.Subject.URIs[j] = ctx.ExpandString(u)
		}
		for j, e := range p.Subject.Emails {
			p.Subject.Emails[j] = ctx.ExpandString(e)
		}

		log.Info("provisioner resolved",
			"name", p.Name,
			"commonName", p.Subject.CommonName,
			"dnsNames", len(p.Subject.DNSNames),
			"ips", len(p.Subject.IPAddresses))
	}

	return nil
}

// applyDefaults fills in missing default values.
func (r *Root) applyDefaults() error {
	s := &r.Settings
	if s.PollInterval == "" {
		s.PollInterval = "15m"
	}
	if s.LogLevel == "" {
		s.LogLevel = "info"
	}
	if s.LogMaxFiles <= 0 {
		s.LogMaxFiles = 3
	}
	if s.Trust.RefreshInterval == "" {
		s.Trust.RefreshInterval = "24h"
	}

	// Resolve base directory: expand env vars, default to <binary_dir>/data
	resolved, err := resolveBaseDirectory(s.BaseDirectory)
	if err != nil {
		return fmt.Errorf("resolve base directory: %w", err)
	}
	s.ResolvedBaseDir = resolved

	for i := range r.Provisioners {
		p := &r.Provisioners[i]
		if p.Key.Algorithm == "" {
			p.Key.Algorithm = "EC"
		}
		if p.Key.Curve == "" && p.Key.Algorithm == "EC" {
			p.Key.Curve = "P256"
		}
		if p.Key.RSABits == 0 && p.Key.Algorithm == "RSA" {
			p.Key.RSABits = 2048
		}
		if !p.Key.GenerateLocal {
			p.Key.GenerateLocal = true
		}
		if p.Renewal.Mode == "" {
			p.Renewal.Mode = "auto"
		}
		if p.Renewal.CheckInterval == "" {
			p.Renewal.CheckInterval = "1h"
		}
		if p.Renewal.Backoff.Initial == "" {
			p.Renewal.Backoff.Initial = "1m"
		}
		if p.Renewal.Backoff.Max == "" {
			p.Renewal.Backoff.Max = "1h"
		}
		if p.Storage.Type == "" {
			p.Storage.Type = "filesystem"
		}
		if p.Storage.Permissions.FileMode == "" {
			p.Storage.Permissions.FileMode = "0600"
		}
	}
	return nil
}

// resolveBaseDirectory expands environment variables in the base directory path
// and returns an absolute path. If empty, defaults to <binary_dir>/data.
// Supports ${env:VARNAME} syntax for environment variable expansion.
func resolveBaseDirectory(configured string) (string, error) {
	if configured == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("get executable path: %w", err)
		}
		return filepath.Join(filepath.Dir(exe), "data"), nil
	}

	// Expand ${env:VARNAME} references
	resolved := expandEnvVars(configured)
	return filepath.Abs(resolved)
}

// expandEnvVars replaces ${env:VARNAME} tokens with their OS environment values.
func expandEnvVars(s string) string {
	for {
		idx := strings.Index(s, "${env:")
		if idx < 0 {
			break
		}
		end := strings.Index(s[idx:], "}")
		if end < 0 {
			break
		}
		varName := s[idx+6 : idx+end]
		val := os.Getenv(varName)
		s = s[:idx] + val + s[idx+end+1:]
	}
	return s
}

// Validate checks required fields and internal consistency.
func (r *Root) Validate() error {
	names := make(map[string]bool)
	for i, p := range r.Provisioners {
		if p.Name == "" {
			return fmt.Errorf("provisioner[%d]: name is required", i)
		}
		if names[p.Name] {
			return fmt.Errorf("provisioner[%d]: duplicate name %q", i, p.Name)
		}
		names[p.Name] = true

		if p.Subject.CommonName == "" && len(p.Subject.DNSNames) == 0 {
			return fmt.Errorf("provisioner[%d] %q: commonName or at least one dnsName is required", i, p.Name)
		}
	}
	return nil
}

// GenerateSample returns a populated sample config as indented JSON bytes.
func GenerateSample() ([]byte, error) {
	sample := Root{
		Settings: Settings{
			LogLevel: "info",
			Bootstrap: Bootstrap{
				CAUrl: "https://ca.example.com",
			},
		},
		Provisioners: []Provisioner{
			{
				Name:    "workstation-identity",
				Enabled: true,
				CAProvisioner: "device-identity",
				Subject: Subject{
					CommonName: "auto",
					DNSNames:   []string{"auto"},
				},
				Auth: Auth{Type: "provisioner-password"},
			},
		},
	}
	return json.MarshalIndent(sample, "", "    ")
}


// LoadFromURL downloads config from a URL and parses it entirely in memory.
// The URL can point to a static .json file, a webhook, or any API endpoint —
// as long as the response body is valid JSON configuration.
// The config is never written to disk; it lives in memory for the lifetime
// of the process. The destPath parameter is ignored (kept for API compat).
// The header and token parameters are optional; when provided, the request
// includes an HTTP header of the form "Header: Token".
func LoadFromURL(url, header, token, destPath string) (*Root, error) {
	log := logging.Logger()
	log.Info("fetching remote configuration (in-memory)", "url", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("config: create request: %w", err)
	}

	if header != "" && token != "" {
		req.Header.Set(header, token)
		log.Info("using authenticated config fetch", "header", header)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("config: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config: fetch %s returned HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("config: read response body: %w", err)
	}
	log.Info("remote config downloaded (held in memory)", "bytes", len(body))

	// Parse JSON directly in memory — no disk write
	var cfg Root
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse remote JSON: %w", err)
	}

	if err := cfg.applyDefaults(); err != nil {
		return nil, fmt.Errorf("config: defaults: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}

	if err := cfg.ResolveVariables(); err != nil {
		log.Warn("config: variable resolution had issues", "error", err)
	}

	log.Info("remote config loaded (in-memory)", "url", url, "provisioners", len(cfg.Provisioners))
	return &cfg, nil
}

func boolPtr(b bool) *bool { return &b }