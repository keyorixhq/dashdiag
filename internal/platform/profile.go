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
	InitSystem string // "systemd", "openrc", "runit", "sysvinit", "unknown"

	// Networking
	NetworkStack string // "networkmanager", "networkd", "netplan", "ifupdown", "unknown"
	HasResolved  bool   // systemd-resolved is active

	// Security modules
	SELinuxMode    string // "enforcing", "permissive", "disabled", "not-present"
	AppArmorActive bool

	// Package manager
	PackageManager string // "apt", "dnf", "tdnf", "yum", "zypper", "pacman", "brew", "unknown"

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
	for line := range strings.SplitSeq(osRelease, "\n") {
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

// detectInitSystem identifies the init system, most specific first. File markers
// alone are NOT enough to tell sysvinit/openrc/runit apart: Devuan ships the runit
// PACKAGE (so /etc/runit and even /run/runit exist) while sysvinit is still PID1,
// and OpenRC uses sysvinit for /sbin/init too. So after the unambiguous systemd
// and openrc-binary markers, the actual PID1 identity from /proc/1/comm is the
// ground truth (verified live on a sysvinit Devuan that had /run/runit present).
// Returns "unknown" when none match (the hint adapter then leaves systemd-form
// remedies alone rather than guessing wrong).
func detectInitSystem() string {
	return detectInitSystemFromPaths("/run/systemd/private", "/sbin/openrc", "/etc/inittab", "/proc/1/comm")
}

// detectInitSystemFromPaths is the testable core of detectInitSystem — injects
// every path it probes so tests never touch the real filesystem/procfs.
func detectInitSystemFromPaths(systemdPriv, openrcBin, inittab, procComm string) string {
	return classifyInit(
		fileExists(systemdPriv),
		fileExists(openrcBin),
		fileExists(inittab),
		pid1CommFromPath(procComm),
	)
}

// classifyInit is the pure decision behind detectInitSystem. systemd and openrc
// are caught by their unambiguous markers; otherwise PID1 identity decides, so a
// sysvinit host carrying the runit package (/run/runit present, PID1 still "init")
// is classified sysvinit, not runit — the trap found live on Devuan.
func classifyInit(hasSystemdPriv, hasOpenrcBin, hasInittab bool, pid1 string) string {
	if hasSystemdPriv {
		return "systemd"
	}
	if hasOpenrcBin {
		return "openrc" // OpenRC runs on a sysvinit PID1; its binary is the marker.
	}
	switch pid1 {
	case "systemd":
		return "systemd"
	case "runit", "runit-init":
		return "runit"
	case "init":
		if hasInittab {
			return "sysvinit"
		}
	}
	return "unknown"
}

// pid1CommFromPath returns the command name of PID 1 from /proc/1/comm
// (world-readable, so it works non-root). "" when unreadable (non-Linux / no procfs).
func pid1CommFromPath(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// detectNetworkStack identifies the active network management layer, in priority
// order. netplan wins only when both the binary and a populated config dir exist.
func detectNetworkStack() string {
	_, lookErr := exec.LookPath("netplan")
	return detectNetworkStackFrom(
		lookErr == nil,
		netplanConfigured(),
		systemctlIsActive("NetworkManager"),
		systemctlIsActive("systemd-networkd"),
		fileExists("/etc/network/interfaces"),
	)
}

// detectNetworkStackFrom is the testable core of detectNetworkStack — the
// priority-ordered decision, with every live probe already resolved to a bool.
func detectNetworkStackFrom(hasNetplanBin, netplanConf, nmActive, networkdActive, hasIfupdown bool) string {
	if hasNetplanBin && netplanConf {
		return "netplan"
	}
	if nmActive {
		return "networkmanager"
	}
	if networkdActive {
		return "networkd"
	}
	if hasIfupdown {
		return "ifupdown"
	}
	return "unknown"
}

// netplanConfigured reports whether /etc/netplan holds at least one .yaml file.
func netplanConfigured() bool {
	return netplanConfiguredInDir("/etc/netplan")
}

// netplanConfiguredInDir is the testable core of netplanConfigured.
func netplanConfiguredInDir(dir string) bool {
	entries, err := os.ReadDir(dir)
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
	for line := range strings.SplitSeq(string(data), "\n") {
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
	return detectAppArmorFromPath("/sys/kernel/security/apparmor/profiles")
}

// detectAppArmorFromPath is the testable core of detectAppArmor.
func detectAppArmorFromPath(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && len(strings.TrimSpace(string(data))) > 0
}

// detectPackageManager returns the first package-manager binary found on PATH.
func detectPackageManager() string {
	return detectPackageManagerWithLookup(exec.LookPath)
}

// detectPackageManagerWithLookup is the testable core of detectPackageManager —
// lookup is exec.LookPath in production, a fake in tests.
func detectPackageManagerWithLookup(lookup func(string) (string, error)) string {
	for _, pm := range []struct{ bin, name string }{
		{"apt-get", "apt"},
		{"dnf", "dnf"},
		// tdnf BEFORE yum: VMware Photon OS ships a `yum` shim that wraps tdnf, so a
		// yum-first probe mislabels Photon as "yum". tdnf is the real manager there.
		{"tdnf", "tdnf"},
		{"yum", "yum"},
		{"zypper", "zypper"},
		{"pacman", "pacman"},
		{"brew", "brew"},
	} {
		if _, err := lookup(pm.bin); err == nil {
			return pm.name
		}
	}
	return "unknown"
}

// systemctlIsActive runs `systemctl is-active <unit>` with a 2s timeout and
// reports whether the unit is active. Returns false fast when systemctl is
// absent (non-systemd hosts, macOS).
func systemctlIsActive(unit string) bool {
	return systemctlIsActiveWithLookup(unit, exec.LookPath)
}

// systemctlIsActiveWithLookup is the testable core of systemctlIsActive's
// fast-absent path — lookup is exec.LookPath in production, a fake in tests.
// The actual `systemctl is-active` invocation still requires a real systemctl
// binary and is not exercised by unit tests.
func systemctlIsActiveWithLookup(unit string, lookup func(string) (string, error)) bool {
	if _, err := lookup("systemctl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", unit).Run() == nil // NOSONAR — hardcoded binary
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
