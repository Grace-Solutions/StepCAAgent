// Package config defines the JSON configuration schema and provides loading,
// validation, and file-permission verification for the agent config.
package config

import (
	"fmt"
	"path/filepath"
)

// ServiceName is the canonical service name, embedded in code rather than config.
const ServiceName = "stepcaagent"

// Root is the top-level configuration structure.
// It contains global settings under Settings and per-certificate
// definitions under Provisioners.
type Root struct {
	Settings     Settings      `json:"Settings"`
	Provisioners []Provisioner `json:"Provisioners"`
}

// Settings holds all global/service-level configuration.
type Settings struct {
	BaseDirectory string       `json:"baseDirectory"` // root for all data; default: <binary_dir>/data
	PollInterval  string       `json:"pollInterval"`
	LogLevel      string       `json:"logLevel"`
	LogMaxFiles   int          `json:"logMaxFiles"`
	Bootstrap     Bootstrap    `json:"bootstrap"`
	ConfigSource  ConfigSource `json:"configSource"`
	Trust         Trust        `json:"trust"`

	// ResolvedBaseDir is computed at load time from BaseDirectory
	// with environment variable expansion applied. Not serialized.
	ResolvedBaseDir string `json:"-"`
}

// Bootstrap holds CA bootstrap parameters.
type Bootstrap struct {
	CAUrl       string `json:"caUrl"`
	Fingerprint string `json:"fingerprint,omitempty"` // optional — auto-detected via TOFU if empty
}

// LogDirectory returns <base>/logs.
func (s Settings) LogDirectory() string {
	return filepath.Join(s.ResolvedBaseDir, "logs")
}

// StateDirectory returns <base>/state.
func (s Settings) StateDirectory() string {
	return filepath.Join(s.ResolvedBaseDir, "state")
}

// CertificatesDirectory returns <base>/certificates.
func (s Settings) CertificatesDirectory() string {
	return filepath.Join(s.ResolvedBaseDir, "certificates")
}

// ConfigSource describes where the config is loaded from.
type ConfigSource struct {
	Type        string            `json:"type"` // "file" or "url"
	Path        string            `json:"path"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	MTLSProfile string            `json:"mtlsProfile"`
	Signature   Signature         `json:"signature"`
}

// Signature holds remote config signature verification options.
type Signature struct {
	Required      bool   `json:"required"`
	PublicKeyPath string `json:"publicKeyPath"`
}

// Trust holds global trust store synchronization settings.
type Trust struct {
	InstallRoots         bool   `json:"installRoots"`
	RefreshInterval      string `json:"refreshInterval"`
	InstallIntermediates bool   `json:"installIntermediates"`
}

// Provisioner defines a single managed certificate.
type Provisioner struct {
	Name           string       `json:"name"`
	Enabled        bool         `json:"enabled"`
	InstallToStore bool         `json:"installToStore"`          // if true, import cert into platform certificate store
	Store          string       `json:"store,omitempty"`         // store scope: "localmachine" (default), "currentuser", "both", or "auto"
	CAProvisioner  string       `json:"caProvisioner,omitempty"` // provisioner name on the CA; defaults to Name if empty
	FriendlyName   string       `json:"friendlyName,omitempty"`  // display name in cert store; "auto" (default) = "StepCA - <name>"
	Subject        Subject      `json:"subject"`
	Key            Key          `json:"key"`
	Renewal        Renewal      `json:"renewal"`
	Storage        Storage      `json:"storage"`
	Auth           Auth         `json:"auth"`
	TrustBinding   TrustBinding `json:"trustBinding"`
	Hooks          Hooks        `json:"-"` // retained for future use; not exposed in config (security: arbitrary command execution)
}

// CAProvisionerName returns the provisioner name to use on the CA.
// If CAProvisioner is set, it takes precedence over Name.
func (p Provisioner) CAProvisionerName() string {
	if p.CAProvisioner != "" {
		return p.CAProvisioner
	}
	return p.Name
}

// ResolvedFriendlyName returns the friendly name to use in the certificate store.
// If FriendlyName is empty or "auto", returns "StepCA - <name>".
func (p Provisioner) ResolvedFriendlyName() string {
	if p.FriendlyName == "" || p.FriendlyName == "auto" {
		return fmt.Sprintf("StepCA - %s", p.Name)
	}
	return p.FriendlyName
}

// ResolvedIntermediateFriendlyName returns the friendly name for the intermediate CA cert.
func (p Provisioner) ResolvedIntermediateFriendlyName() string {
	return fmt.Sprintf("%s (Intermediate)", p.ResolvedFriendlyName())
}

// Subject holds certificate subject/SAN fields.
type Subject struct {
	CommonName  string   `json:"commonName"`
	DNSNames    []string `json:"dnsNames"`
	IPAddresses []string `json:"ipAddresses"`
	URIs        []string `json:"uris"`
	Emails      []string `json:"emails"`
}

// Key defines key generation parameters.
type Key struct {
	Algorithm     string `json:"algorithm"` // "EC", "RSA"
	Curve         string `json:"curve"`     // "P256", "P384", etc.
	RSABits       int    `json:"rsaBits"`
	GenerateLocal bool   `json:"generateLocally"`
	NonExportable *bool  `json:"nonExportable"` // defaults to true if nil
}

// IsNonExportable returns the effective non-exportable setting (default true).
func (k Key) IsNonExportable() bool {
	if k.NonExportable == nil {
		return true
	}
	return *k.NonExportable
}

// Renewal defines automatic renewal behaviour.
type Renewal struct {
	Mode          string  `json:"mode"` // "auto", "manual"
	RenewBefore   string  `json:"renewBefore"`
	CheckInterval string  `json:"checkInterval"`
	Jitter        string  `json:"jitter"`
	Backoff       Backoff `json:"backoff"`
}

// Backoff defines retry backoff parameters.
type Backoff struct {
	Initial string `json:"initial"`
	Max     string `json:"max"`
}

// Storage defines where the certificate and key are placed.
// Paths are always derived from the base directory:
// <base>/certificates/<provisioner>/certificate.crt, private.key, chain.crt
type Storage struct {
	Type        string          `json:"type"` // "filesystem", "store"
	Permissions FilePermissions `json:"permissions"`
}

// FilePermissions defines ownership and mode for output files.
type FilePermissions struct {
	Owner    string `json:"owner"`
	Group    string `json:"group"`
	FileMode string `json:"fileMode"`
}

// Auth holds per-provisioner enrollment credentials.
type Auth struct {
	Type      string `json:"type"` // "provisioner-password", "jwk", "bootstrap-token", "acme"
	Password  string `json:"password"`
	TokenPath string `json:"tokenPath"`
	JWKPath   string `json:"jwkPath"`
}

// TrustBinding controls trust chain installation for this cert.
type TrustBinding struct {
	InstallIssuedChain    bool `json:"installIssuedChain"`
	ValidateCAFingerprint bool `json:"validateCaFingerprint"`
}

// Hooks defines post-operation commands.
// Currently disabled from JSON deserialization to prevent agent-takeover via
// arbitrary command execution. The struct is retained for potential future use
// (e.g., webhook-based notifications).
type Hooks struct {
	PostInstall []string `json:"postInstall"`
	PostRenew   []string `json:"postRenew"`
}

