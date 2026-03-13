// Package vars implements variable expansion for config fields.
// Supported variables:
//
//	${hostname}       - machine hostname (lowercase)
//	${fqdn}           - hostname.primary-dns-suffix (if available)
//	${domain}         - primary DNS suffix/search domain
//	${ip}             - first eligible IP address
//	${serial}         - device hardware serial number
//	${fqdn_1}         - hostname.first-dns-suffix (same as ${fqdn}), ${fqdn_2} second, etc.
//	${dns_suffix_1}   - first DNS suffix, ${dns_suffix_2} second, etc.
//	${ipv4_1}         - first IPv4 address, ${ipv4_2} second, etc.
//	${ipv6_1}         - first IPv6 address, ${ipv6_2} second, etc.
//	auto              - expands to all detected values (hostname, FQDNs, IPs)
package vars

import (
	"fmt"
	"os"
	"strings"

	"github.com/GraceSolutions/StepCAAgent/internal/discovery"
	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// Context holds resolved variable values for expansion.
type Context struct {
	Hostname    string
	FQDN        string
	Domain      string
	IP          string
	Serial      string
	IsWindowsPE bool
	Auto        *discovery.Result

	// Indexed variables (populated during construction)
	indexedVars map[string]string
}

// NewContext builds a variable context using auto-discovery.
func NewContext() (*Context, error) {
	log := logging.Logger()
	log.Info("building variable context")

	result, err := discovery.Detect()
	if err != nil {
		return nil, err
	}

	ctx := &Context{
		Hostname: strings.ToLower(result.Hostname),
		Auto:     result,
	}

	if len(result.SearchDomains) > 0 {
		ctx.Domain = result.SearchDomains[0]
		if ctx.Hostname != "" {
			ctx.FQDN = ctx.Hostname + "." + ctx.Domain
		}
	}

	if len(result.IPAddresses) > 0 {
		ctx.IP = result.IPAddresses[0]
	}

	ctx.Serial = result.SerialNumber
	ctx.IsWindowsPE = result.IsWindowsPE

	// Build indexed variables
	ctx.indexedVars = make(map[string]string)

	// DNS suffixes: ${dns_suffix_1}, ${dns_suffix_2}, ...
	for i, suffix := range result.SearchDomains {
		ctx.indexedVars[fmt.Sprintf("${dns_suffix_%d}", i+1)] = suffix
	}

	// Indexed FQDNs: ${fqdn_1} (same as ${fqdn}), ${fqdn_2}, ${fqdn_3}, ...
	if ctx.Hostname != "" {
		for i, suffix := range result.SearchDomains {
			fqdn := ctx.Hostname + "." + suffix
			ctx.indexedVars[fmt.Sprintf("${fqdn_%d}", i+1)] = fqdn
		}
	}

	// IPv4 addresses: ${ipv4_1}, ${ipv4_2}, ...
	for i, ip := range result.IPv4Addresses {
		ctx.indexedVars[fmt.Sprintf("${ipv4_%d}", i+1)] = ip
	}

	// IPv6 addresses: ${ipv6_1}, ${ipv6_2}, ...
	for i, ip := range result.IPv6Addresses {
		ctx.indexedVars[fmt.Sprintf("${ipv6_%d}", i+1)] = ip
	}

	log.Info("variable context built",
		"hostname", ctx.Hostname,
		"fqdn", ctx.FQDN,
		"domain", ctx.Domain,
		"ip", ctx.IP,
		"serial", ctx.Serial,
		"winpe", ctx.IsWindowsPE,
		"dns_suffixes", len(result.SearchDomains),
		"ipv4_count", len(result.IPv4Addresses),
		"ipv6_count", len(result.IPv6Addresses))

	return ctx, nil
}

// ExpandString replaces ${variable} placeholders in a string.
func (c *Context) ExpandString(s string) string {
	if s == "" {
		return s
	}

	s = strings.ReplaceAll(s, "${hostname}", c.Hostname)
	s = strings.ReplaceAll(s, "${fqdn}", c.FQDN)
	s = strings.ReplaceAll(s, "${domain}", c.Domain)
	s = strings.ReplaceAll(s, "${ip}", c.IP)
	s = strings.ReplaceAll(s, "${serial}", c.Serial)

	// Indexed variables: ${dns_suffix_N}, ${ipv4_NNNNN}, ${ipv6_NNNNN}
	for key, val := range c.indexedVars {
		s = strings.ReplaceAll(s, key, val)
	}

	// OS-level env vars: ${env:VARNAME}
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

// HasAuto returns true if "auto" appears in the given slice.
func HasAuto(values []string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), "auto") {
			return true
		}
	}
	return false
}

// StripAuto removes "auto" entries from a slice and returns the rest.
func StripAuto(values []string) []string {
	var result []string
	for _, v := range values {
		if !strings.EqualFold(strings.TrimSpace(v), "auto") {
			result = append(result, v)
		}
	}
	return result
}

// ResolveDNSNames resolves a dnsNames list, expanding "auto" if present.
// When auto is used and a serial number is detected AND we're in WindowsPE,
// the serial is included as a DNS SAN. On regular Windows/Linux/macOS the
// serial is available as ${serial} but not auto-included in SANs.
func (c *Context) ResolveDNSNames(raw []string) []string {
	if HasAuto(raw) {
		explicit := StripAuto(raw)
		// Expand variables in explicit entries
		for i, v := range explicit {
			explicit[i] = c.ExpandString(v)
		}
		autoNames := c.Auto.DNSNames
		// Include serial number as a SAN ONLY in WindowsPE
		if c.Serial != "" && c.IsWindowsPE {
			autoNames = append(autoNames, c.Serial)
		}
		return discovery.MergeUnique(autoNames, explicit)
	}
	// Just expand variables
	result := make([]string, len(raw))
	for i, v := range raw {
		result[i] = c.ExpandString(v)
	}
	return result
}

// ResolveIPAddresses resolves an ipAddresses list, expanding "auto" if present.
func (c *Context) ResolveIPAddresses(raw []string) []string {
	if HasAuto(raw) {
		explicit := StripAuto(raw)
		for i, v := range explicit {
			explicit[i] = c.ExpandString(v)
		}
		return discovery.MergeUnique(c.Auto.IPAddresses, explicit)
	}
	result := make([]string, len(raw))
	for i, v := range raw {
		result[i] = c.ExpandString(v)
	}
	return result
}

// ResolveCommonName resolves commonName, expanding "auto" to hostname.
func (c *Context) ResolveCommonName(raw string) string {
	if strings.EqualFold(strings.TrimSpace(raw), "auto") {
		if c.FQDN != "" {
			return c.FQDN
		}
		return c.Hostname
	}
	return c.ExpandString(raw)
}

