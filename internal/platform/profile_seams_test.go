package platform

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestPid1CommFromPath covers both the happy path (comm file readable) and the
// absent-file fallback ("") that detectInitSystemFromPaths relies on to fall
// through to "unknown" rather than misreading a missing procfs entry as some
// init system name.
func TestPid1CommFromPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "comm-present")
		if err := os.WriteFile(path, []byte("systemd\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := pid1CommFromPath(path); got != "systemd" {
			t.Errorf("pid1CommFromPath = %q, want systemd", got)
		}
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		if got := pid1CommFromPath(filepath.Join(dir, "does-not-exist")); got != "" {
			t.Errorf("pid1CommFromPath(absent) = %q, want empty", got)
		}
	})
}

// TestDetectInitSystemFromPaths exercises the full priority chain (systemd
// marker > openrc marker > pid1 identity) through injected paths only — no
// real filesystem/procfs access.
func TestDetectInitSystemFromPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "absent")
	commPath := filepath.Join(dir, "comm")

	cases := []struct {
		name                          string
		systemdPresent, openrcPresent bool
		inittabPresent                bool
		comm                          string
		want                          string
	}{
		{"systemd marker wins", true, false, false, "", "systemd"},
		{"openrc marker wins over pid1", false, true, false, "init", "openrc"},
		{"pid1 systemd fallback", false, false, false, "systemd", "systemd"},
		{"pid1 runit", false, false, false, "runit", "runit"},
		{"pid1 init with inittab", false, false, true, "init", "sysvinit"},
		{"pid1 init without inittab", false, false, false, "init", "unknown"},
		{"nothing matches", false, false, false, "", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			systemdPath, openrcPath, inittabPath := absent, absent, absent
			if tc.systemdPresent {
				systemdPath = present
			}
			if tc.openrcPresent {
				openrcPath = present
			}
			if tc.inittabPresent {
				inittabPath = present
			}
			myComm := filepath.Join(commPath, tc.name)
			if tc.comm != "" {
				if err := os.MkdirAll(filepath.Dir(myComm), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(myComm, []byte(tc.comm), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got := detectInitSystemFromPaths(systemdPath, openrcPath, inittabPath, myComm)
			if got != tc.want {
				t.Errorf("detectInitSystemFromPaths(...) = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNetplanConfiguredInDir(t *testing.T) {
	t.Parallel()

	t.Run("absent dir", func(t *testing.T) {
		t.Parallel()
		if netplanConfiguredInDir(filepath.Join(t.TempDir(), "nope")) {
			t.Error("expected false for missing dir")
		}
	})

	t.Run("empty dir", func(t *testing.T) {
		t.Parallel()
		if netplanConfiguredInDir(t.TempDir()) {
			t.Error("expected false for empty dir")
		}
	})

	t.Run("has yaml", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "01-netcfg.yaml"), []byte("network: {}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !netplanConfiguredInDir(dir) {
			t.Error("expected true when a .yaml file is present")
		}
	})

	t.Run("has non-yaml only", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "README"), []byte("nope"), 0o600); err != nil {
			t.Fatal(err)
		}
		if netplanConfiguredInDir(dir) {
			t.Error("expected false when only non-yaml files present")
		}
	})
}

func TestDetectNetworkStackFrom(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                                                       string
		hasNetplanBin, netplanConf, nmActive, networkdActive, ifup bool
		want                                                       string
	}{
		{"netplan wins when bin+config present", true, true, true, true, true, "netplan"},
		{"netplan bin without config falls through", true, false, true, false, false, "networkmanager"},
		{"networkmanager", false, false, true, false, false, "networkmanager"},
		{"networkd", false, false, false, true, false, "networkd"},
		{"ifupdown", false, false, false, false, true, "ifupdown"},
		{"unknown", false, false, false, false, false, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := detectNetworkStackFrom(tc.hasNetplanBin, tc.netplanConf, tc.nmActive, tc.networkdActive, tc.ifup)
			if got != tc.want {
				t.Errorf("detectNetworkStackFrom(...) = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetectAppArmorFromPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	cases := []struct {
		name    string
		content *string // nil → file absent
		want    bool
	}{
		{"absent", nil, false},
		{"empty", new(""), false},
		{"whitespace only", new("   \n"), false},
		{"has profiles", new("/usr/sbin/sshd (enforce)\n"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, tc.name)
			if tc.content != nil {
				if err := os.WriteFile(path, []byte(*tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := detectAppArmorFromPath(path); got != tc.want {
				t.Errorf("detectAppArmorFromPath(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestDetectPackageManagerWithLookup(t *testing.T) {
	t.Parallel()

	fakeLookup := func(present ...string) func(string) (string, error) {
		set := make(map[string]bool, len(present))
		for _, p := range present {
			set[p] = true
		}
		return func(bin string) (string, error) {
			if set[bin] {
				return "/usr/bin/" + bin, nil
			}
			return "", errors.New("not found")
		}
	}

	cases := []struct {
		name    string
		present []string
		want    string
	}{
		{"apt", []string{"apt-get"}, "apt"},
		{"dnf", []string{"dnf"}, "dnf"},
		// tdnf before yum: Photon OS ships a yum shim over tdnf.
		{"tdnf wins over yum", []string{"tdnf", "yum"}, "tdnf"},
		{"yum alone", []string{"yum"}, "yum"},
		{"zypper", []string{"zypper"}, "zypper"},
		{"pacman", []string{"pacman"}, "pacman"},
		{"brew", []string{"brew"}, "brew"},
		{"none found", nil, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := detectPackageManagerWithLookup(fakeLookup(tc.present...))
			if got != tc.want {
				t.Errorf("detectPackageManagerWithLookup(%v) = %q, want %q", tc.present, got, tc.want)
			}
		})
	}
}

func TestSystemctlIsActiveWithLookup_Absent(t *testing.T) {
	t.Parallel()
	absentLookup := func(string) (string, error) { return "", errors.New("not found") }
	if systemctlIsActiveWithLookup("some-unit", absentLookup) {
		t.Error("expected false when systemctl binary is absent")
	}
}

// TestSystemctlIsActiveWithLookup_Present exercises the branch where lookup
// succeeds and the real `systemctl is-active` invocation runs. The unit name
// is deliberately implausible so that on hosts where systemctl IS installed
// the command still exits non-zero (inactive/not-found), and on hosts where
// it isn't installed exec.CommandContext itself fails to start — either way
// the function must return false without panicking, and the exec branch
// (previously uncovered) executes.
func TestSystemctlIsActiveWithLookup_Present(t *testing.T) {
	t.Parallel()
	presentLookup := func(string) (string, error) { return "/usr/bin/systemctl", nil }
	if systemctlIsActiveWithLookup("dashdiag-test-unit-that-does-not-exist", presentLookup) {
		t.Error("expected false for a nonexistent unit")
	}
}

// TestDetect_RealPaths is a smoke test for the production Detect() wrapper:
// it hits the real /etc/os-release and the chain of real-path detectors
// (detectInitSystem, detectNetworkStack, detectResolved, detectSELinux,
// detectAppArmor, detectPackageManager) on whatever host runs the suite. It
// can't assert specific field values (host-dependent), only that the call
// completes without panicking and returns internally consistent output — the
// actual parsing/decision logic is exhaustively covered via detectFromContent
// and the *FromPaths/*WithLookup seams elsewhere in this file.
func TestDetect_RealPaths(t *testing.T) {
	t.Parallel()
	p := Detect()
	if p.OS == "" {
		t.Error("Detect().OS is empty, want runtime.GOOS")
	}
	if p.OS == "darwin" && p.PackageManager != "brew" {
		t.Errorf("Detect() on darwin: PackageManager = %q, want brew", p.PackageManager)
	}
}

// TestDetectFromContent covers the testable core Detect() delegates to after
// reading /etc/os-release: it wires together parseOSRelease with the live
// real-path detectors, so the assertions here can only check the fields
// parseOSRelease controls; the live-probed fields (InitSystem, NetworkStack,
// etc.) are host-dependent and are exhaustively covered separately via their
// *FromPaths/*WithLookup seams.
func TestDetectFromContent(t *testing.T) {
	t.Parallel()
	p := detectFromContent(Profile{OS: "linux"}, ubuntu2404)
	if p.Distro != "ubuntu" {
		t.Errorf("detectFromContent Distro = %q, want ubuntu", p.Distro)
	}
	if p.MajorVersion != 24 {
		t.Errorf("detectFromContent MajorVersion = %d, want 24", p.MajorVersion)
	}
	// InitSystem/NetworkStack/PackageManager/etc. are set from live host probes
	// (not from the injected os-release content) — just assert the call wired
	// them to *some* value rather than leaving the zero-value "" for a string
	// field that detectInitSystem/detectPackageManager always populate.
	if p.InitSystem == "" {
		t.Error("detectFromContent InitSystem is empty, want a value from detectInitSystem")
	}
	if p.PackageManager == "" {
		t.Error("detectFromContent PackageManager is empty, want a value from detectPackageManager")
	}
}

// TestDetectInitSystem_RealPath / TestDetectNetworkStack_RealPath /
// TestNetplanConfigured_RealPath / TestDetectResolved_RealPath /
// TestDetectSELinux_RealPath / TestDetectAppArmor_RealPath /
// TestDetectPackageManager_RealPath / TestSystemctlIsActive_RealPath are smoke
// tests for the production real-path wrappers. Each delegates to a fully
// covered *FromPaths/*WithLookup core, so these only assert the call
// completes without panicking on whatever host runs the suite.
func TestDetectInitSystem_RealPath(t *testing.T) {
	t.Parallel()
	got := detectInitSystem()
	if got == "" {
		t.Error("detectInitSystem() returned empty string, want a value (possibly \"unknown\")")
	}
}

func TestDetectNetworkStack_RealPath(t *testing.T) {
	t.Parallel()
	got := detectNetworkStack()
	if got == "" {
		t.Error("detectNetworkStack() returned empty string, want a value (possibly \"unknown\")")
	}
}

func TestNetplanConfigured_RealPath(t *testing.T) {
	t.Parallel()
	// Must not panic; result is host-dependent.
	_ = netplanConfigured()
}

func TestDetectResolved_RealPath(t *testing.T) {
	t.Parallel()
	// Must not panic; result is host-dependent.
	_ = detectResolved()
}

func TestDetectSELinux_RealPath(t *testing.T) {
	t.Parallel()
	got := detectSELinux()
	switch got {
	case "enforcing", "permissive", "disabled", "not-present":
		// expected
	default:
		t.Errorf("detectSELinux() = %q, not a recognized SELinux mode", got)
	}
}

func TestDetectAppArmor_RealPath(t *testing.T) {
	t.Parallel()
	// Must not panic; result is host-dependent.
	_ = detectAppArmor()
}

func TestDetectPackageManager_RealPath(t *testing.T) {
	t.Parallel()
	got := detectPackageManager()
	if got == "" {
		t.Error("detectPackageManager() returned empty string, want a value (possibly \"unknown\")")
	}
}

func TestSystemctlIsActive_RealPath(t *testing.T) {
	t.Parallel()
	// Must not panic; result is host-dependent.
	_ = systemctlIsActive("dashdiag-test-unit-that-does-not-exist")
}

func TestDebugLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		p    Profile
		want string
	}{
		{
			"selinux enforcing",
			Profile{Distro: "rhel", DistroVersion: "10.1", NetworkStack: "networkmanager", SELinuxMode: "enforcing", PackageManager: "dnf"},
			"rhel 10.1, networkmanager, SELinux enforcing, dnf",
		},
		{
			"apparmor active, no selinux",
			Profile{Distro: "ubuntu", DistroVersion: "24.04", NetworkStack: "netplan", SELinuxMode: "not-present", AppArmorActive: true, PackageManager: "apt"},
			"ubuntu 24.04, netplan, AppArmor, apt",
		},
		{
			"neither selinux nor apparmor",
			Profile{Distro: "nixos", DistroVersion: "25.05", NetworkStack: "networkd", SELinuxMode: "not-present", PackageManager: "unknown"},
			"nixos 25.05, networkd, SELinux not-present, unknown",
		},
		{
			"empty distro falls back to OS",
			Profile{OS: "linux", NetworkStack: "unknown", SELinuxMode: "not-present", PackageManager: "unknown"},
			"linux, unknown, SELinux not-present, unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.p.DebugLine(); got != tc.want {
				t.Errorf("DebugLine() = %q, want %q", got, tc.want)
			}
		})
	}
}
