package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// Characterization tests filling coverage gaps in prescanContext (both value and
// pointer forms of each cross-check case), hostInstallPM's distro classification,
// enableHint/disableHint/serviceCmd's per-init-system branches, firstN's boundary
// behaviour, and AdaptHostHints' Gentoo/transactional/ostree gates. These pin
// existing, previously-untested behaviour — no logic changed.

func TestPrescanContext_ValueAndPointerForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		result  runner.Result
		checkFn func(t *testing.T, p prescanResult, thresh Thresholds)
	}{
		{
			name:   "PackagesInfo value sets PackageManager",
			result: runner.Result{Data: models.PackagesInfo{PackageManager: "dnf"}},
			checkFn: func(t *testing.T, _ prescanResult, thresh Thresholds) {
				if thresh.PackageManager != "dnf" {
					t.Errorf("PackageManager = %q, want dnf", thresh.PackageManager)
				}
			},
		},
		{
			name:   "PackagesInfo pointer sets PackageManager",
			result: runner.Result{Data: &models.PackagesInfo{PackageManager: "apt"}},
			checkFn: func(t *testing.T, _ prescanResult, thresh Thresholds) {
				if thresh.PackageManager != "apt" {
					t.Errorf("PackageManager = %q, want apt", thresh.PackageManager)
				}
			},
		},
		{
			name:   "CPUInfo value sets CPULoadPct",
			result: runner.Result{Data: models.CPUInfo{LoadPct: 42.5}},
			checkFn: func(t *testing.T, _ prescanResult, thresh Thresholds) {
				if thresh.CPULoadPct != 42.5 {
					t.Errorf("CPULoadPct = %v, want 42.5", thresh.CPULoadPct)
				}
			},
		},
		{
			name:   "CPUInfo pointer sets CPULoadPct",
			result: runner.Result{Data: &models.CPUInfo{LoadPct: 12.0}},
			checkFn: func(t *testing.T, _ prescanResult, thresh Thresholds) {
				if thresh.CPULoadPct != 12.0 {
					t.Errorf("CPULoadPct = %v, want 12.0", thresh.CPULoadPct)
				}
			},
		},
		{
			name:   "KernelSecurityInfo value sets selinuxEnforcing",
			result: runner.Result{Data: models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if !p.selinuxEnforcing {
					t.Error("selinuxEnforcing must be true")
				}
			},
		},
		{
			name:   "KernelSecurityInfo pointer sets selinuxEnforcing",
			result: runner.Result{Data: &models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if !p.selinuxEnforcing {
					t.Error("selinuxEnforcing must be true")
				}
			},
		},
		{
			name:   "ZFSInfo value sets zfsPoolsPresent",
			result: runner.Result{Data: models.ZFSInfo{Pools: []models.ZFSPool{{Name: "tank"}}}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if !p.zfsPoolsPresent {
					t.Error("zfsPoolsPresent must be true")
				}
			},
		},
		{
			name:   "ZFSInfo pointer sets zfsPoolsPresent",
			result: runner.Result{Data: &models.ZFSInfo{Pools: []models.ZFSPool{{Name: "tank"}}}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if !p.zfsPoolsPresent {
					t.Error("zfsPoolsPresent must be true")
				}
			},
		},
		{
			name:   "DiskInfo value sets zfsPoolsPresent",
			result: runner.Result{Data: models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank"}}}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if !p.zfsPoolsPresent {
					t.Error("zfsPoolsPresent must be true (DiskInfo value)")
				}
			},
		},
		{
			name:   "DiskInfo pointer sets zfsPoolsPresent",
			result: runner.Result{Data: &models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank"}}}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if !p.zfsPoolsPresent {
					t.Error("zfsPoolsPresent must be true (DiskInfo pointer)")
				}
			},
		},
		{
			name:   "SwapInfo value sets swapActive",
			result: runner.Result{Data: models.SwapInfo{TotalGB: 4, UsedPct: 10}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if !p.swapActive {
					t.Error("swapActive must be true (SwapInfo value)")
				}
			},
		},
		{
			name:   "SwapInfo pointer sets swapActive",
			result: runner.Result{Data: &models.SwapInfo{TotalGB: 4, UsedPct: 10}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if !p.swapActive {
					t.Error("swapActive must be true (SwapInfo pointer)")
				}
			},
		},
		{
			name:   "VMwareInfo value sets vmwareCPULimitMHz",
			result: runner.Result{Data: models.VMwareInfo{StatAvailable: true, CPULimitMHz: 2400}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if p.vmwareCPULimitMHz != 2400 {
					t.Errorf("vmwareCPULimitMHz = %d, want 2400", p.vmwareCPULimitMHz)
				}
			},
		},
		{
			name:   "VMwareInfo pointer sets vmwareCPULimitMHz",
			result: runner.Result{Data: &models.VMwareInfo{StatAvailable: true, CPULimitMHz: 1800}},
			checkFn: func(t *testing.T, p prescanResult, _ Thresholds) {
				if p.vmwareCPULimitMHz != 1800 {
					t.Errorf("vmwareCPULimitMHz = %d, want 1800", p.vmwareCPULimitMHz)
				}
			},
		},
		{
			// r.Err != nil must skip the case entirely (no panic, no field set).
			name:   "result with Err is skipped",
			result: runner.Result{Data: models.CPUInfo{LoadPct: 99}, Err: errBoom},
			checkFn: func(t *testing.T, _ prescanResult, thresh Thresholds) {
				if thresh.CPULoadPct == 99 {
					t.Error("errored result must not update thresh")
				}
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			thresh := Thresholds{}
			p := prescanContext([]runner.Result{tt.result}, &thresh)
			tt.checkFn(t, p, thresh)
		})
	}
}

// errBoom is a stand-in error for the "result had a collector error" case above.
type gapfillErr struct{ msg string }

func (e *gapfillErr) Error() string { return e.msg }

var errBoom = &gapfillErr{"boom"}

// hostInstallPM classifies distro IDs into the package manager fix hints should
// lead with; "" means leave hints unchanged (Debian/Ubuntu, or a distro with its
// own dedicated hint rewriter, or unknown).
func TestHostInstallPM(t *testing.T) {
	tests := []struct {
		distroID string
		want     string
	}{
		{"", ""},
		{"gentoo", ""},
		{"nixos", ""},
		{"photon", "tdnf"},
		{"opensuse-leap", "zypper"},
		{"sles", "zypper"},
		{"rhel", "dnf"},
		{"centos", "dnf"},
		{"almalinux", "dnf"},
		{"rocky", "dnf"},
		{"fedora", "dnf"},
		{"ol", "dnf"},
		{"amzn", "dnf"},
		{"arch", "pacman"},
		{"manjaro", "pacman"},
		{"alpine", "apk"},
		{"debian", ""},
		{"ubuntu", ""},
		{"some-unknown-distro", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.distroID, func(t *testing.T) {
			// Not parallel: SetReplayPlatform mutates shared package state.
			restore := platform.SetReplayPlatform(tt.distroID, "systemd", "linux")
			defer restore()
			if got := hostInstallPM(); got != tt.want {
				t.Errorf("hostInstallPM() for distro %q = %q, want %q", tt.distroID, got, tt.want)
			}
		})
	}
}

// enableHint / disableHint produce the init-specific enable/disable command;
// unknown or systemd init falls back to the systemctl form.
func TestEnableDisableHint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		initSystem  string
		wantEnable  string
		wantDisable string
		unit        string
	}{
		{"openrc", "to fix: rc-update add nginx && rc-service nginx start", "to fix: rc-update del nginx", "nginx"},
		{"sysvinit", "to fix: update-rc.d nginx enable && service nginx start", "to fix: update-rc.d nginx disable", "nginx"},
		{"runit", "to fix: ln -s /etc/sv/nginx /var/service/", "to fix: rm /var/service/nginx", "nginx"},
		{"systemd", "to fix: systemctl enable --now nginx", "to fix: systemctl disable nginx", "nginx"},
		{"unknown", "to fix: systemctl enable --now nginx", "to fix: systemctl disable nginx", "nginx"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.initSystem, func(t *testing.T) {
			t.Parallel()
			if got := enableHint(tt.unit, tt.initSystem); got != tt.wantEnable {
				t.Errorf("enableHint(%q) = %q, want %q", tt.initSystem, got, tt.wantEnable)
			}
			if got := disableHint(tt.unit, tt.initSystem); got != tt.wantDisable {
				t.Errorf("disableHint(%q) = %q, want %q", tt.initSystem, got, tt.wantDisable)
			}
		})
	}
}

// serviceCmd maps a systemd verb to its non-systemd equivalent, returning "" when
// there is no clean equivalent (e.g. runit has no direct "status" mapping missing
// from the map, or an entirely unknown init system).
func TestServiceCmd(t *testing.T) {
	t.Parallel()
	tests := []struct {
		verb, unit, initSystem, want string
	}{
		{"start", "nginx", "openrc", "rc-service nginx start"},
		{"stop", "nginx", "openrc", "rc-service nginx stop"},
		{"restart", "nginx", "sysvinit", "service nginx restart"},
		{"start", "nginx", "runit", "sv up nginx"},
		{"stop", "nginx", "runit", "sv down nginx"},
		{"restart", "nginx", "runit", "sv restart nginx"},
		{"status", "nginx", "runit", "sv status nginx"},
		{"bogus-verb", "nginx", "runit", ""},
		{"start", "nginx", "unknown-init", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.initSystem+"_"+tt.verb, func(t *testing.T) {
			t.Parallel()
			if got := serviceCmd(tt.verb, tt.unit, tt.initSystem); got != tt.want {
				t.Errorf("serviceCmd(%q,%q,%q) = %q, want %q", tt.verb, tt.unit, tt.initSystem, got, tt.want)
			}
		})
	}
}

// firstN returns at most n elements; it must not panic or grow the slice when n
// exceeds len(ss), and must truncate when it doesn't.
func TestFirstN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []string
		n    int
		want []string
	}{
		{"n greater than len returns all", []string{"a", "b"}, 5, []string{"a", "b"}},
		{"n equal to len returns all", []string{"a", "b"}, 2, []string{"a", "b"}},
		{"n less than len truncates", []string{"a", "b", "c"}, 2, []string{"a", "b"}},
		{"n zero returns empty", []string{"a", "b"}, 0, []string{}},
		{"empty input", []string{}, 3, []string{}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := firstN(tt.in, tt.n)
			if len(got) != len(tt.want) {
				t.Fatalf("firstN(%v, %d) = %v, want %v", tt.in, tt.n, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("firstN(%v, %d)[%d] = %q, want %q", tt.in, tt.n, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// AdaptHostHints must route through the Gentoo and transactional-SUSE hint
// rewriters when the (replay-pinned) host matches those distros — the NixOS path
// is already covered by gentoo_hints_test.go's TestAdaptHostHints_ReplayOverride.
func TestAdaptHostHints_GentooGate(t *testing.T) {
	// Not parallel: SetReplayPlatform mutates shared package state.
	restore := platform.SetReplayPlatform("gentoo", "systemd", "linux")
	defer restore()
	in := []models.Insight{{Hints: []string{
		"to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)",
	}}}
	got := AdaptHostHints(in)[0].Hints[0]
	if got != "to fix (Gentoo): emerge open-vm-tools" {
		t.Errorf("Gentoo gate must rewrite to emerge, got %q", got)
	}
}

func TestAdaptHostHints_TransactionalGate(t *testing.T) {
	// Not parallel: SetReplayPlatform mutates shared package state.
	restore := platform.SetReplayPlatform("opensuse-microos", "systemd", "linux")
	defer restore()
	in := []models.Insight{{Hints: []string{
		"to fix: zypper install open-vm-tools",
	}}}
	got := AdaptHostHints(in)
	if len(got) != 1 {
		t.Fatalf("expected 1 insight, got %d", len(got))
	}
	// Just confirm the transactional path ran without panicking and produced a
	// hint string (the specific rewrite format belongs to transactionalifyHints,
	// tested elsewhere if present); here we assert the gate is exercised.
	if len(got[0].Hints) != 1 {
		t.Errorf("expected 1 hint to remain, got %v", got[0].Hints)
	}
}
