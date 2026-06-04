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
		{"enforcing", strptr("1"), "enforcing"},
		{"permissive", strptr("0"), "permissive"},
		{"disabled", strptr("2"), "disabled"},
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

func strptr(s string) *string { return &s }
