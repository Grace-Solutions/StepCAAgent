//go:build windows

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

// detectSerialNumber retrieves the device serial number on Windows.
// It runs on both full Windows and WindowsPE. VM serial numbers are
// filtered out since they are not unique across instances.
// The serial is always made available as a ${serial} variable;
// whether it's included as a SAN is controlled separately.
func detectSerialNumber() string {
	log := logging.Logger()
	log.Info("auto-discovery: attempting serial number detection on Windows")

	// Method 1: BIOS serial (most reliable, works in WinPE)
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-WmiObject -Class Win32_BIOS).SerialNumber").CombinedOutput()
	if err == nil {
		serial := strings.TrimSpace(string(out))
		if isValidPhysicalSerial(serial) {
			log.Info("auto-discovery: serial number detected via BIOS", "serial", serial)
			return serial
		}
	} else {
		log.Debug("auto-discovery: Win32_BIOS serial query failed", "error", err)
	}

	// Method 2: System enclosure serial
	out, err = exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-WmiObject -Class Win32_SystemEnclosure).SerialNumber").CombinedOutput()
	if err == nil {
		serial := strings.TrimSpace(string(out))
		if isValidPhysicalSerial(serial) {
			log.Info("auto-discovery: serial number detected via SystemEnclosure", "serial", serial)
			return serial
		}
	} else {
		log.Debug("auto-discovery: Win32_SystemEnclosure serial query failed", "error", err)
	}

	// Method 3: Computer system product serial
	out, err = exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-WmiObject -Class Win32_ComputerSystemProduct).IdentifyingNumber").CombinedOutput()
	if err == nil {
		serial := strings.TrimSpace(string(out))
		if isValidPhysicalSerial(serial) {
			log.Info("auto-discovery: serial number detected via ComputerSystemProduct", "serial", serial)
			return serial
		}
	} else {
		log.Debug("auto-discovery: Win32_ComputerSystemProduct serial query failed", "error", err)
	}

	log.Warn("auto-discovery: could not detect physical device serial number in WindowsPE")
	return ""
}

// detectIsWindowsPE is the exported-style function used by discovery.Detect().
func detectIsWindowsPE() bool {
	return isWindowsPE()
}

// isWindowsPE detects whether we are running inside a Windows PE environment.
// WinPE boots from X:\ and lacks a normal %SystemRoot%\System32 install.
func isWindowsPE() bool {
	// Primary check: X:\Windows is the typical WinPE system root
	if sr := os.Getenv("SystemRoot"); strings.HasPrefix(strings.ToUpper(sr), "X:") {
		return true
	}

	// Secondary: check for the WinPE marker registry-equivalent file
	if _, err := os.Stat(`X:\Windows\System32\winpe.ini`); err == nil {
		return true
	}

	// Tertiary: check for the WinPE-specific PENetwork executable
	if _, err := os.Stat(`X:\Windows\System32\wpeinit.exe`); err == nil {
		return true
	}

	return false
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

