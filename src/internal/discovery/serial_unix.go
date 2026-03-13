//go:build !windows

package discovery

import (
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
)

// vmSerialPattern matches serial numbers from virtual machines of any
// manufacturer. These are excluded because VM serial numbers are typically
// not unique across instances. Case-insensitive.
var vmSerialPattern = regexp.MustCompile(
	`(?i)` +
		`(vmware|virtual|vm[- ]|` + // VMware, generic virtual
		`ec2[a-z0-9-]|` + // AWS EC2 instance IDs
		`i-[0-9a-f]{8,}|` + // AWS instance IDs
		`google|gce|` + // Google Cloud
		`azure|` + // Microsoft Azure
		`qemu|kvm|` + // QEMU/KVM
		`xen|` + // Xen
		`parallels|` + // Parallels
		`vbox|virtualbox|` + // VirtualBox
		`bhyve|` + // bhyve
		`nutanix|` + // Nutanix AHV
		`openstack|` + // OpenStack
		`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`, // UUID-style serials (common in VMs)
)

// detectSerialNumber retrieves the device serial number on Linux/macOS.
// VM serial numbers are filtered out since they are not unique.
// The serial is always made available as a ${serial} variable;
// whether it's included as a SAN is controlled separately.
func detectSerialNumber() string {
	log := logging.Logger()
	log.Info("auto-discovery: attempting serial number detection")

	// Linux: /sys/class/dmi/id/product_serial (requires root)
	if data, err := os.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
		serial := strings.TrimSpace(string(data))
		if isValidPhysicalSerial(serial) {
			log.Info("auto-discovery: serial number detected via DMI", "serial", serial)
			return serial
		}
	}

	// macOS: system_profiler
	out, err := exec.Command("system_profiler", "SPHardwareDataType").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Serial Number") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					serial := strings.TrimSpace(parts[1])
					if isValidPhysicalSerial(serial) {
						log.Info("auto-discovery: serial number detected via system_profiler", "serial", serial)
						return serial
					}
				}
			}
		}
	}

	// Linux fallback: dmidecode
	out, err = exec.Command("dmidecode", "-s", "system-serial-number").CombinedOutput()
	if err == nil {
		serial := strings.TrimSpace(string(out))
		if isValidPhysicalSerial(serial) {
			log.Info("auto-discovery: serial number detected via dmidecode", "serial", serial)
			return serial
		}
	}

	log.Warn("auto-discovery: could not detect device serial number")
	return ""
}

// isValidPhysicalSerial returns true if the serial looks like a real
// physical hardware serial — not a placeholder and not a VM serial.
func isValidPhysicalSerial(s string) bool {
	if s == "" {
		return false
	}
	if isPlaceholderSerial(s) {
		return false
	}
	if vmSerialPattern.MatchString(s) {
		return false
	}
	return true
}

// detectIsWindowsPE always returns false on non-Windows platforms.
func detectIsWindowsPE() bool {
	return false
}

// isPlaceholderSerial returns true for common placeholder/default serial values.
func isPlaceholderSerial(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	placeholders := []string{
		"to be filled by o.e.m.",
		"to be filled by o.e.m",
		"default string",
		"none",
		"not specified",
		"system serial number",
		"0",
		"",
	}
	for _, p := range placeholders {
		if lower == p {
			return true
		}
	}
	return false
}

