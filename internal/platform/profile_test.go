package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// osReleaseFixtures are representative /etc/os-release bodies per distro family.
var (
	rhel101 = `NAME="Red Hat Enterprise Linux"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="10.1"
PRETTY_NAME="Red Hat Enterprise Linux 10.1"`

	debian12 = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=debian`

	ubuntu2404 = `PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian`

	sles156 = `NAME="SLES"
VERSION_ID="15.6"
ID="sles"
ID_LIKE="suse"`

	opensuseLeap16 = `NAME="openSUSE Leap"
VERSION_ID="16.0"
ID="opensuse-leap"
ID_LIKE="suse opensuse"`

	nixos2505 = `NAME=NixOS
ID=nixos
VERSION_ID="25.05"
VERSION_CODENAME=warbler`

	steamos37 = `NAME="SteamOS"
ID=steamos
ID_LIKE="arch"
VERSION_ID="3.7"
VARIANT_ID=steamdeck`

	almalinux94 = `NAME="AlmaLinux"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"`

	rocky10 = `NAME="Rocky Linux"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="10.0"`
)

func TestParseOSRelease(t *testing.T) {
	cases := []struct {
		name        string
		content     string
		wantDistro  string
		wantMajor   int
		wantCode    string
		wantSyslog  string
		wantAuthLog string
		wantSteamOS bool
	}{
		{"rhel-10.1", rhel101, "rhel", 10, "", "/var/log/messages", "/var/log/secure", false},
		{"debian-12", debian12, "debian", 12, "bookworm", "/var/log/syslog", "/var/log/auth.log", false},
		{"ubuntu-24.04", ubuntu2404, "ubuntu", 24, "noble", "/var/log/syslog", "/var/log/auth.log", false},
		{"sles-15.6", sles156, "sles", 15, "", "/var/log/messages", "/var/log/secure", false},
		{"opensuse-leap-16", opensuseLeap16, "opensuse", 16, "", "/var/log/messages", "/var/log/secure", false},
		{"nixos-25.05", nixos2505, "nixos", 25, "warbler", "", "", false},
		{"steamos-3.7", steamos37, "steamos", 3, "", "", "", true},
		{"almalinux-9.4", almalinux94, "rhel", 9, "", "/var/log/messages", "/var/log/secure", false},
		{"rocky-10", rocky10, "rhel", 10, "", "/var/log/messages", "/var/log/secure", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Profile{OS: "linux"}
			parseOSRelease(&p, tc.content)
			setLogPaths(&p)

			if p.Distro != tc.wantDistro {
				t.Errorf("Distro = %q, want %q", p.Distro, tc.wantDistro)
			}
			if p.MajorVersion != tc.wantMajor {
				t.Errorf("MajorVersion = %d, want %d", p.MajorVersion, tc.wantMajor)
			}
			if p.Codename != tc.wantCode {
				t.Errorf("Codename = %q, want %q", p.Codename, tc.wantCode)
			}
			if p.SyslogPath != tc.wantSyslog {
				t.Errorf("SyslogPath = %q, want %q", p.SyslogPath, tc.wantSyslog)
			}
			if p.AuthLogPath != tc.wantAuthLog {
				t.Errorf("AuthLogPath = %q, want %q", p.AuthLogPath, tc.wantAuthLog)
			}
			if p.IsSteamOS != tc.wantSteamOS {
				t.Errorf("IsSteamOS = %v, want %v", p.IsSteamOS, tc.wantSteamOS)
			}
		})
	}
}

func TestDetectDarwin(t *testing.T) {
	// Detect() short-circuits on darwin; emulate that path's invariants directly
	// so the test is meaningful on any host.
	p := Profile{OS: "darwin", PackageManager: "brew"}
	if p.OS != "darwin" {
		t.Errorf("OS = %q, want darwin", p.OS)
	}
	if p.PackageManager != "brew" {
		t.Errorf("PackageManager = %q, want brew", p.PackageManager)
	}
	if p.Distro != "" {
		t.Errorf("Distro = %q, want empty", p.Distro)
	}
	// macOS leaves all log paths empty.
	setLogPaths(&p)
	if p.SyslogPath != "" || p.AuthLogPath != "" || p.AuditLogPath != "" {
		t.Errorf("darwin log paths should be empty, got syslog=%q auth=%q audit=%q",
			p.SyslogPath, p.AuthLogPath, p.AuditLogPath)
	}
}

func TestNormalizeDistroPreservesUnknown(t *testing.T) {
	// Unknown IDs must be preserved verbatim, not mapped to "unknown".
	if got := normalizeDistro("gentoo"); got != "gentoo" {
		t.Errorf("normalizeDistro(gentoo) = %q, want gentoo", got)
	}
}

func TestDetectSELinuxFromPath(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		content *string // nil → file absent
		want    string
	}{
		{"absent", nil, "not-present"},
		{"enforcing", new("1"), "enforcing"},
		{"permissive", new("0"), "permissive"},
		{"disabled", new("2"), "disabled"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if tc.content != nil {
				if err := os.WriteFile(path, []byte(*tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := detectSELinuxFromPath(path); got != tc.want {
				t.Errorf("detectSELinuxFromPath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetectSELinuxFromPaths_ConfigDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	if err := os.WriteFile(cfg, []byte("# comment\nSELINUX=disabled\nSELINUXTYPE=targeted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	absentEnforce := filepath.Join(dir, "no-enforce")

	// enforce node absent + config says disabled → "disabled" (not "not-present").
	if got := detectSELinuxFromPaths(absentEnforce, cfg); got != "disabled" {
		t.Errorf("config-disabled SELinux = %q, want disabled", got)
	}
	// enforce node absent + no config → "not-present".
	if got := detectSELinuxFromPaths(absentEnforce, filepath.Join(dir, "no-config")); got != "not-present" {
		t.Errorf("no SELinux at all = %q, want not-present", got)
	}
	// enforce node present (enforcing) wins regardless of config.
	enf := filepath.Join(dir, "enforce")
	_ = os.WriteFile(enf, []byte("1"), 0o600)
	if got := detectSELinuxFromPaths(enf, cfg); got != "enforcing" {
		t.Errorf("enforcing host = %q, want enforcing", got)
	}
}

// classifyInit must use PID1 identity, not file markers, to tell sysvinit from
// runit: Devuan ships the runit package (so /run/runit exists) while sysvinit is
// PID1. A marker-only check mis-classified that host as runit and emitted `sv …`
// hints instead of `service …` (found live on Devuan 6, 2026-06-29).
func TestClassifyInit(t *testing.T) {
	cases := []struct {
		name                            string
		systemdPriv, openrcBin, inittab bool
		pid1                            string
		want                            string
	}{
		{"systemd", true, false, false, "systemd", "systemd"},
		{"openrc binary (sysvinit pid1)", false, true, true, "init", "openrc"},
		{"devuan sysvinit with runit package", false, false, true, "init", "sysvinit"},
		{"runit as pid1", false, false, false, "runit", "runit"},
		{"runit-init pid1 variant", false, false, false, "runit-init", "runit"},
		{"sysvinit but no inittab → unknown", false, false, false, "init", "unknown"},
		{"systemd via pid1 fallback", false, false, false, "systemd", "systemd"},
		{"nothing known", false, false, false, "", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyInit(c.systemdPriv, c.openrcBin, c.inittab, c.pid1); got != c.want {
				t.Errorf("classifyInit(%v,%v,%v,%q) = %q, want %q", c.systemdPriv, c.openrcBin, c.inittab, c.pid1, got, c.want)
			}
		})
	}
}
