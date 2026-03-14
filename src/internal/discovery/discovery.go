// Package discovery detects local hostname, DNS suffixes, search domains,
// and IP addresses for automatic SAN population.
package discovery

import (
	"net"
	"os"
	"sort"
	"strings"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// Result holds the auto-detected identity values.
type Result struct {
	Hostname      string
	DNSNames      []string // hostname, hostname.suffix for each suffix
	IPAddresses   []string // filtered to public, RFC1918, CGNAT
	IPv4Addresses []string // IPv4 only
	IPv6Addresses []string // IPv6 only
	SearchDomains []string // raw search domains found
	SerialNumber  string   // device hardware serial number
	IsWindowsPE   bool     // true when running inside Windows PE
	OSName        string   // e.g. "Microsoft Windows 11 Pro", "Ubuntu 22.04"
	OSVersion     string   // e.g. "10.0.22631", "22.04"
	OSProductType string   // "Server" or "Client"
}

// OSInfo holds operating system metadata returned by platform-specific detection.
type OSInfo struct {
	Name        string // full OS name/caption
	Version     string // OS version string
	ProductType string // "Server" or "Client"
}

// Detect performs auto-discovery of the local machine's identity.
func Detect() (*Result, error) {
	log := logging.Logger()
	log.Info("auto-discovery starting")

	r := &Result{}
	var err error

	// 1. Hostname
	r.Hostname, err = os.Hostname()
	if err != nil {
		log.Warn("auto-discovery: could not get hostname", "error", err)
		r.Hostname = ""
	} else {
		log.Info("auto-discovery: hostname detected", "hostname", r.Hostname)
	}

	// 2. DNS suffixes and search domains
	suffixes := detectDNSSuffixes()
	r.SearchDomains = suffixes
	log.Info("auto-discovery: DNS suffixes detected", "count", len(suffixes), "suffixes", strings.Join(suffixes, ","))

	// 3. Build DNS names: hostname, then hostname.suffix for each suffix
	seen := make(map[string]bool)
	if r.Hostname != "" {
		lower := strings.ToLower(r.Hostname)
		r.DNSNames = append(r.DNSNames, lower)
		seen[lower] = true
		for _, suffix := range suffixes {
			fqdn := strings.ToLower(r.Hostname + "." + suffix)
			if !seen[fqdn] {
				r.DNSNames = append(r.DNSNames, fqdn)
				seen[fqdn] = true
			}
		}
	}

	// 4. IP addresses (public, RFC1918, CGNAT only)
	r.IPAddresses = detectIPs()
	// Separate IPv4 and IPv6
	for _, ip := range r.IPAddresses {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			r.IPv4Addresses = append(r.IPv4Addresses, ip)
		} else {
			r.IPv6Addresses = append(r.IPv6Addresses, ip)
		}
	}
	log.Info("auto-discovery: IPs detected",
		"total", len(r.IPAddresses),
		"ipv4", len(r.IPv4Addresses),
		"ipv6", len(r.IPv6Addresses))

	// 5. Device serial number (detected on all platforms, VM serials filtered)
	r.SerialNumber = detectSerialNumber()
	if r.SerialNumber != "" {
		log.Info("auto-discovery: serial number detected", "serial", r.SerialNumber)
	}

	// 6. WindowsPE detection
	r.IsWindowsPE = detectIsWindowsPE()
	if r.IsWindowsPE {
		log.Info("auto-discovery: running in WindowsPE environment")
	}

	// 7. OS information
	osInfo := detectOSInfo()
	r.OSName = osInfo.Name
	r.OSVersion = osInfo.Version
	r.OSProductType = osInfo.ProductType
	if r.OSName != "" {
		log.Info("auto-discovery: OS detected",
			"name", r.OSName,
			"version", r.OSVersion,
			"productType", r.OSProductType)
	}

	log.Info("auto-discovery complete",
		"dnsNames", len(r.DNSNames),
		"ipv4", len(r.IPv4Addresses),
		"ipv6", len(r.IPv6Addresses),
		"serial", r.SerialNumber,
		"winpe", r.IsWindowsPE,
		"os", r.OSName,
		"osType", r.OSProductType)
	return r, nil
}

// detectIPs returns IP addresses from up interfaces that are public, RFC1918, or CGNAT.
func detectIPs() []string {
	log := logging.Logger()
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Warn("auto-discovery: could not list interfaces", "error", err)
		return nil
	}

	seen := make(map[string]bool)
	var ips []string

	for _, iface := range ifaces {
		// Skip down, loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Debug("auto-discovery: could not get addrs for interface", "iface", iface.Name, "error", err)
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			if isEligibleIP(ip) {
				s := ip.String()
				if !seen[s] {
					seen[s] = true
					ips = append(ips, s)
				}
			}
		}
	}

	sort.Strings(ips)
	return ips
}

// isEligibleIP returns true if the IP is public, RFC1918, or CGNAT.
func isEligibleIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// RFC1918
	if isRFC1918(ip) {
		return true
	}
	// CGNAT (100.64.0.0/10)
	if isCGNAT(ip) {
		return true
	}
	// Public: not private, not link-local, not loopback
	if ip.IsGlobalUnicast() && !ip.IsPrivate() {
		return true
	}
	// ip.IsPrivate() covers RFC1918 already, so also include those
	if ip.IsPrivate() {
		return true
	}
	return false
}

// isRFC1918 checks 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
func isRFC1918(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return (ip4[0] == 10) ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168)
}

// isCGNAT checks 100.64.0.0/10
func isCGNAT(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 100.64.0.0/10 = 100.64.0.0 - 100.127.255.255
	return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}

// MergeUnique merges auto-detected values with explicitly provided values,
// returning a deduplicated list preserving order.
func MergeUnique(auto, explicit []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range auto {
		lower := strings.ToLower(strings.TrimSpace(v))
		if lower != "" && !seen[lower] {
			seen[lower] = true
			result = append(result, lower)
		}
	}
	for _, v := range explicit {
		lower := strings.ToLower(strings.TrimSpace(v))
		if lower != "" && lower != "auto" && !seen[lower] {
			seen[lower] = true
			result = append(result, lower)
		}
	}
	return result
}

