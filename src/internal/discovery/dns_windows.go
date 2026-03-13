//go:build windows

package discovery

import (
	"os/exec"
	"strings"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

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
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" && !seen[s] {
				seen[s] = true
				result = append(result, s)
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
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" && !seen[s] {
				seen[s] = true
				result = append(result, s)
			}
		}
	} else {
		log.Debug("auto-discovery: Get-DnsClient suffix failed", "error", err)
	}

	return result
}

