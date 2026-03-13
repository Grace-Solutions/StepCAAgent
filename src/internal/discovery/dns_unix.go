//go:build !windows

package discovery

import (
	"os"
	"strings"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// detectDNSSuffixes returns DNS suffixes and search domains on Unix
// by parsing /etc/resolv.conf.
func detectDNSSuffixes() []string {
	log := logging.Logger()
	seen := make(map[string]bool)
	var result []string

	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		log.Debug("auto-discovery: could not read /etc/resolv.conf", "error", err)
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		// "domain example.com" or "search example.com foo.bar"
		if strings.HasPrefix(line, "domain ") || strings.HasPrefix(line, "search ") {
			fields := strings.Fields(line)
			for _, f := range fields[1:] {
				s := strings.ToLower(strings.TrimSpace(f))
				if s != "" && !seen[s] {
					seen[s] = true
					result = append(result, s)
				}
			}
		}
	}

	return result
}

