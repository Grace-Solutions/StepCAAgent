//go:build windows

package discovery

import (
	"os/exec"
	"regexp"
	"strings"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// reSpace matches one or more whitespace characters.
var reSpace = regexp.MustCompile(`[[:space:]]+`)

// detectDNSSuffixes returns DNS suffixes and search domains on Windows
// using PowerShell to query network adapter configurations.
func detectDNSSuffixes() []string {
	log := logging.Logger()
	seen := make(map[string]bool)
	var result []string

	// Method 1: Get-DnsClientGlobalSetting
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-DnsClientGlobalSetting).SuffixSearchList -join ','").CombinedOutput()
	if err == nil {
		for _, s := range strings.Split(strings.TrimSpace(string(out)), ",") {
			for _, part := range splitSuffix(s) {
				if !seen[part] {
					seen[part] = true
					result = append(result, part)
				}
			}
		}
	} else {
		log.Debug("auto-discovery: Get-DnsClientGlobalSetting failed", "error", err)
	}

	// Method 2: Per-adapter connection-specific suffixes
	out, err = exec.Command("powershell", "-NoProfile", "-Command",
		"Get-DnsClient | Where-Object {$_.ConnectionSpecificSuffix -ne ''} | Select-Object -ExpandProperty ConnectionSpecificSuffix").CombinedOutput()
	if err == nil {
		for _, s := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			for _, part := range splitSuffix(s) {
				if !seen[part] {
					seen[part] = true
					result = append(result, part)
				}
			}
		}
	} else {
		log.Debug("auto-discovery: Get-DnsClient suffix failed", "error", err)
	}

	return result
}

// splitSuffix splits a raw suffix string at whitespace boundaries,
// lowercases each token, and returns only non-empty results.
// PowerShell can return entries like "ts.net lan" that are really two suffixes.
func splitSuffix(raw string) []string {
	var out []string
	for _, token := range reSpace.Split(strings.TrimSpace(raw), -1) {
		token = strings.ToLower(strings.TrimSpace(token))
		if token != "" {
			out = append(out, token)
		}
	}
	return out
}
