package platform

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Profile is the centralized, distro-normalized view of the host platform.
// It is the single source of truth for distro-specific paths and behaviour
// (SteamOS specs, log path resolution, package-manager-aware fix commands),
// replacing scattered ad-hoc /etc/os-release reads across collectors.
type Profile struct {
	// OS identity
	OS     string // "linux", "darwin"
	Distro string // normalized ID: "rhel", "debian", "ubuntu", "sles", "arch",
	// "nixos", "opensuse", "steamos", or the raw ID for unknowns
	DistroVersion string // raw VERSION_ID: "10.1", "22.04", "15.6"
	MajorVersion  int    // parsed major: 10, 22, 15
	Codename      string // VERSION_CODENAME: "bookworm", "noble", ""
	IsSteamOS     bool   // ID=steamos OR VARIANT_ID=steamdeck

	// Init system
	InitSystem string // "systemd", "openrc", "unknown"

	// Networking
	NetworkStack string // "networkmanager", "networkd", "netplan", "ifupdown", "unknown"
	HasResolved  bool   // systemd-resolved is active

	// Security modules
	SELinuxMode    string // "enforcing", "permissive", "disabled", "not-present"
	AppArmorActive bool

	// Package manager
	PackageManager string // "apt", "dnf", "yum", "zypper", "pacman", "brew", "unknown"

	// Log paths (distro-resolved)
	SyslogPath   string // "/var/log/syslog" or "/var/log/messages" or ""
	AuthLogPath  string // "/var/log/auth.log" or "/var/log/secure" or ""
	AuditLogPath string // "/var/log/audit/audit.log" or ""
}

// Detect builds a Profile for the live host. It reads real files; the parsing
// core is split into detectFromContent so tests can inject os-release content
// without touching the filesystem.
func Detect() Profile {
	p := Profile{OS: runtime.GOOS}
	if runtime.GOOS == "darwin" {
		p.PackageManager = "brew"
		return p
	}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return p
	}
	return detectFromContent(p, string(data))
}

// detectFromContent is the testable core — it parses os-release content and
// probes live system state (systemctl, file existence) for the dynamic fields.
func detectFromContent(p Profile, osRelease string) Profile {
	parseOSRelease(&p, osRelease)
	p.InitSystem = detectInitSystem()
	p.NetworkStack = detectNetworkStack()
	p.HasResolved = detectResolved()
	p.SELinuxMode = detectSELinux()
	p.AppArmorActive = detectAppArmor()
	p.PackageManager = detectPackageManager()
	setLogPaths(&p)
	return p
}

// parseOSRelease fills the static identity fields from /etc/os-release content.
func parseOSRelease(p *Profile, osRelease string) {
	var id, variantID string
	for _, line := range strings.Split(osRelease, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, `"'`)
		switch key {
		case "ID":
			id = strings.ToLower(val)
		case "VARIANT_ID":
			variantID = strings.ToLower(val)
		case "VERSION_ID":
			p.DistroVersion = val
		case "VERSION_CODENAME":
			p.Codename = strings.ToLower(val)
		}
	}

	p.Distro = normalizeDistro(id)
	if id == "steamos" || variantID == "steamdeck" {
		p.IsSteamOS = true
		p.Distro = "steamos"
	}
	p.MajorVersion = parseMajor(p.DistroVersion)
}

// normalizeDistro maps the raw os-release ID to a canonical distro family.
// Unknown IDs are preserved verbatim so future distros still get a stable key.
func normalizeDistro(id string) string {
	switch id {
	case "rhel", "centos", "rocky", "almalinux", "fedora":
		return "rhel"
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "sles", "sle-micro":
		return "sles"
	case "opensuse-leap", "opensuse-tumbleweed":
		return "opensuse"
	case "arch", "manjaro", "endeavouros":
		return "arch"
	case "nixos":
		return "nixos"
	case "steamos":
		return "steamos"
	default:
		return id
	}
}

// parseMajor extracts the leading integer of a VERSION_ID ("10.1" → 10).
func parseMajor(versionID string) int {
	major, _, _ := strings.Cut(versionID, ".")
	n, err := strconv.Atoi(strings.TrimSpace(major))
	if err != nil {
		return 0
	}
	return n
}

// setLogPaths resolves the distro-specific text log paths. journald-only
// distros (NixOS, SteamOS) and macOS get empty syslog/auth paths.
func setLogPaths(p *Profile) {
	switch p.Distro {
	case "rhel", "opensuse", "sles", "arch":
		p.SyslogPath = "/var/log/messages"
		p.AuthLogPath = "/var/log/secure"
	case "debian", "ubuntu":
		p.SyslogPath = "/var/log/syslog"
		p.AuthLogPath = "/var/log/auth.log"
	}
	// AuditLogPath is the same across distros; existence is checked at runtime.
	if p.OS == "linux" {
		p.AuditLogPath = "/var/log/audit/audit.log"
	}
}

// detectInitSystem identifies the init system from well-known runtime markers.
func detectInitSystem() string {
	if fileExists("/run/systemd/private") {
		return "systemd"
	}
	if fileExists("/sbin/openrc") {
		return "openrc"
	}
	return "unknown"
}

// detectNetworkStack identifies the active network management layer, in priority
// order. netplan wins only when both the binary and a populated config dir exist.
func detectNetworkStack() string {
	if _, err := exec.LookPath("netplan"); err == nil && netplanConfigured() {
		return "netplan"
	}
	if systemctlIsActive("NetworkManager") {
		return "networkmanager"
	}
	if systemctlIsActive("systemd-networkd") {
		return "networkd"
	}
	if fileExists("/etc/network/interfaces") {
		return "ifupdown"
	}
	return "unknown"
}

// netplanConfigured reports whether /etc/netplan holds at least one .yaml file.
func netplanConfigured() bool {
	entries, err := os.ReadDir("/etc/netplan")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			return true
		}
	}
	return false
}

// detectResolved reports whether systemd-resolved is active.
func detectResolved() bool {
	return systemctlIsActive("systemd-resolved")
}

// detectSELinux reports the SELinux mode from /sys/fs/selinux/enforce, falling
// back to /etc/selinux/config to tell a config-disabled install ("disabled")
// from a system without SELinux at all ("not-present").
func detectSELinux() string {
	return detectSELinuxFromPaths("/sys/fs/selinux/enforce", "/etc/selinux/config")
}

// detectSELinuxFromPaths layers the /etc/selinux/config check on top of the
// enforce-node read: when the enforce node is absent (SELinux not mounted) but
// the config explicitly says SELINUX=disabled, report "disabled" rather than
// "not-present" — the former is an actionable admin choice, the latter just
// means the distro ships no SELinux.
func detectSELinuxFromPaths(enforcePath, configPath string) string {
	mode := detectSELinuxFromPath(enforcePath)
	if mode == "not-present" && selinuxConfigDisabled(configPath) {
		return "disabled"
	}
	return mode
}

// selinuxConfigDisabled reports whether /etc/selinux/config sets SELINUX=disabled.
func selinuxConfigDisabled(configPath string) bool {
	data, err := os.ReadFile(configPath) // #nosec G304 -- fixed system path
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "SELINUX="); ok {
			return strings.TrimSpace(v) == "disabled"
		}
	}
	return false
}

// detectSELinuxFromPath is the testable core of detectSELinux.
func detectSELinuxFromPath(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "not-present"
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		return "enforcing"
	case "0":
		return "permissive"
	default:
		return "disabled"
	}
}

// detectAppArmor reports whether AppArmor has profiles loaded.
func detectAppArmor() bool {
	data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	return err == nil && len(strings.TrimSpace(string(data))) > 0
}

// detectPackageManager returns the first package-manager binary found on PATH.
func detectPackageManager() string {
	for _, pm := range []struct{ bin, name string }{
		{"apt-get", "apt"},
		{"dnf", "dnf"},
		{"yum", "yum"},
		{"zypper", "zypper"},
		{"pacman", "pacman"},
		{"brew", "brew"},
	} {
		if _, err := exec.LookPath(pm.bin); err == nil {
			return pm.name
		}
	}
	return "unknown"
}

// systemctlIsActive runs `systemctl is-active <unit>` with a 2s timeout and
// reports whether the unit is active. Returns false fast when systemctl is
// absent (non-systemd hosts, macOS).
func systemctlIsActive(unit string) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", unit).Run() == nil
}

// DebugLine renders a one-line platform summary for `--debug` output.
// Example: "rhel 10.1, networkmanager, SELinux enforcing, dnf".
func (p Profile) DebugLine() string {
	sec := "SELinux " + p.SELinuxMode
	if p.AppArmorActive && p.SELinuxMode == "not-present" {
		sec = "AppArmor"
	}
	distro := p.Distro
	if distro == "" {
		distro = p.OS
	}
	return strings.Join([]string{
		strings.TrimSpace(distro + " " + p.DistroVersion),
		p.NetworkStack,
		sec,
		p.PackageManager,
	}, ", ")
}
