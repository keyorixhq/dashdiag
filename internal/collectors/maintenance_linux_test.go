//go:build linux

package collectors

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestKdumpKernelPatchKspliceIdentity guards the Name()/Timeout() identity
// methods for the three container-context-gated host-kernel collectors.
func TestKdumpKernelPatchKspliceIdentity(t *testing.T) {
	t.Parallel()

	kd := NewKdumpCollector(platform.ContainerContext{})
	if kd.Name() != "Kdump" {
		t.Errorf("KdumpCollector.Name() = %q, want Kdump", kd.Name())
	}
	if kd.Timeout() != 3*time.Second {
		t.Errorf("KdumpCollector.Timeout() = %v, want 3s", kd.Timeout())
	}

	kp := NewKernelPatchCollector(platform.ContainerContext{})
	if kp.Name() != "Kernel" {
		t.Errorf("KernelPatchCollector.Name() = %q, want Kernel", kp.Name())
	}
	if kp.Timeout() != 5*time.Second {
		t.Errorf("KernelPatchCollector.Timeout() = %v, want 5s", kp.Timeout())
	}

	ks := NewKspliceCollector(platform.ContainerContext{})
	if ks.Name() != "Ksplice" {
		t.Errorf("KspliceCollector.Name() = %q, want Ksplice", ks.Name())
	}
	if ks.Timeout() != 6*time.Second {
		t.Errorf("KspliceCollector.Timeout() = %v, want 6s", ks.Timeout())
	}
}

// TestClassifyLivePatchEnabled guards the non-root false-alarm: an unreadable "enabled"
// sysfs attribute (EACCES under a non-root run, or kernel lockdown) must classify as
// UNVERIFIED, never disabled. Reporting an unreadable-but-healthy patch as disabled would
// WARN that the kernel runs un-patched code when it doesn't. The error is injected because
// the test runs as root (in CI's container too), where root bypasses the permission bits —
// so a real 0400 file would read fine; the pure classifier is what makes this testable.
func TestClassifyLivePatchEnabled(t *testing.T) {
	eacces := &os.PathError{Op: "open", Path: "/sys/kernel/livepatch/klp_fix/enabled", Err: syscall.EACCES}
	cases := []struct {
		name    string
		content string
		err     error
		want    livePatchState
	}{
		{"enabled", "1\n", nil, livePatchEnabled},
		{"disabled", "0\n", nil, livePatchDisabled},
		{"disabled no newline", "0", nil, livePatchDisabled},
		{"permission denied is unverified", "", eacces, livePatchUnverified},
		{"any read error is unverified", "", os.ErrNotExist, livePatchUnverified},
		// A read error must win even if stale/garbled content came back alongside it.
		{"error beats content", "1", eacces, livePatchUnverified},
	}
	for _, c := range cases {
		if got := classifyLivePatchEnabled(c.content, c.err); got != c.want {
			t.Errorf("%s: classifyLivePatchEnabled(%q, %v) = %d, want %d", c.name, c.content, c.err, got, c.want)
		}
	}
}

// TestSUSERebootSignalExitCodes guards BUG-088: the SUSE Kernel row keyed on
// `zypper needs-rebooting` STDOUT, but under root a sibling zypper collector holds
// the zypp lock so needs-rebooting fails fast with exit 7 and EMPTY stdout → the
// whole Kernel row was silently dropped under root (proven via a capture bundle on
// real SLES 16). The fix keys on the EXIT CODE and surfaces a held lock as
// "couldn't determine" instead of dropping the row. Each subtest scripts one exit.
func TestSUSERebootSignalExitCodes(t *testing.T) {
	cases := []struct {
		name               string
		exit               int
		ctxDone            bool // expired ctx so the locked path doesn't really sleep 4s
		wantOK, wantReboot bool
		wantUnverified     bool
	}{
		{name: "exit0_no_reboot", exit: 0, wantOK: true},
		{name: "exit102_reboot_needed", exit: 102, wantOK: true, wantReboot: true},
		{name: "exit7_locked_is_unverified_not_dropped", exit: 7, ctxDone: true, wantOK: true, wantUnverified: true},
		{name: "other_error_falls_through", exit: 4, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakeRunSource{run: func(name string, _ []string) source.Result {
				return source.Result{ExitCode: tc.exit}
			}}
			defer SetSource(SetSource(fake))

			ctx := context.Background()
			if tc.ctxDone {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			ok, reboot, unverified := suseRebootSignal(ctx)
			if ok != tc.wantOK || reboot != tc.wantReboot || unverified != tc.wantUnverified {
				t.Fatalf("exit %d: got (ok=%v reboot=%v unverified=%v), want (ok=%v reboot=%v unverified=%v)",
					tc.exit, ok, reboot, unverified, tc.wantOK, tc.wantReboot, tc.wantUnverified)
			}
			// The critical invariant: a held lock must NEVER read as a clean reboot=false
			// OK row — it must be flagged unverified so health shows INFO, not "Kernel OK".
			if tc.exit == 7 && !unverified {
				t.Fatal("ZYPP_LOCKED (exit 7) must surface as unverified, never a silent OK")
			}
		})
	}
}

// TestMaintenanceSkip pins the host-kernel gate, including the #655 regression:
// kdump/kernel/Ksplice are host-kernel concerns, so they must skip inside a
// container EVEN when the subsystem looks present (a container can't reboot or
// kdump the host kernel it shares). Dropping the container term would silently
// reintroduce the "Kernel OK reported the host's kernel" false-OK.
func TestMaintenanceSkip(t *testing.T) {
	cases := []struct {
		name        string
		available   bool
		inContainer bool
		wantSkip    bool
	}{
		{"present on a host → run", true, false, false},
		{"present in a container → SKIP (host-kernel concern)", true, true, true},
		{"absent on a host → skip", false, false, true},
		{"absent in a container → skip", false, true, true},
	}
	for _, c := range cases {
		if got := maintenanceSkip(c.available, c.inContainer); got != c.wantSkip {
			t.Errorf("%s: maintenanceSkip(%v,%v)=%v, want %v", c.name, c.available, c.inContainer, got, c.wantSkip)
		}
	}
}

// TestHostKernelCollectorsGateOffInContainer is the end-to-end pin: with the
// container context injected (now a constructor param, not hidden global state),
// the three host-kernel collectors report Available=false; ServiceRestart, which
// is per-process and stays valid in a container, is not gated here.
func TestHostKernelCollectorsGateOffInContainer(t *testing.T) {
	inCtr := platform.ContainerContext{InContainer: true}
	if v, _ := NewKdumpCollector(inCtr).Collect(context.Background()); v.(*models.KdumpInfo).Available {
		t.Error("Kdump must gate off in a container")
	}
	if v, _ := NewKernelPatchCollector(inCtr).Collect(context.Background()); v.(*models.KernelPatchInfo).Available {
		t.Error("Kernel must gate off in a container")
	}
	if v, _ := NewKspliceCollector(inCtr).Collect(context.Background()); v.(*models.KspliceInfo).Available {
		t.Error("Ksplice must gate off in a container")
	}
}

func TestKernelNVRAToUname(t *testing.T) {
	cases := map[string]string{
		"kernel-uek-6.12.0-203.76.7.5.el10uek.x86_64": "6.12.0-203.76.7.5.el10uek.x86_64",
		"kernel-core-5.14.0-687.17.1.el9_8.x86_64":    "5.14.0-687.17.1.el9_8.x86_64",
		"kernel-5.14.0-687.17.1.el9_8.x86_64":         "5.14.0-687.17.1.el9_8.x86_64",
		"kernel-uek-core-6.12.0-1.el10uek.x86_64":     "6.12.0-1.el10uek.x86_64",
		"5.14.0-687.17.1.el9_8.x86_64":                "5.14.0-687.17.1.el9_8.x86_64", // no package prefix -> unchanged
	}
	for in, want := range cases {
		if got := kernelNVRAToUname(in); got != want {
			t.Errorf("kernelNVRAToUname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapsHasDeletedLib(t *testing.T) {
	stale := `7f0a00000000-7f0a00021000 r-xp 00000000 fd:00 1234  /usr/lib64/libc.so.6 (deleted)
7f0a00021000-7f0a00022000 r--p 00021000 fd:00 1234  /usr/lib64/libc.so.6 (deleted)`
	if !mapsHasDeletedLib(stale) {
		t.Error("a deleted system .so must be detected")
	}
	// A deleted temp file (not a .so / not a lib dir) must NOT count.
	tmp := `7f0a00000000-7f0a00021000 rw-p 00000000 fd:00 99  /tmp/scratch.dat (deleted)`
	if mapsHasDeletedLib(tmp) {
		t.Error("a deleted non-lib temp file must NOT count as a stale library")
	}
	// A live mapping (no deleted marker) must not count.
	live := `7f0a00000000-7f0a00021000 r-xp 00000000 fd:00 1234  /usr/lib64/libssl.so.3`
	if mapsHasDeletedLib(live) {
		t.Error("a current (non-deleted) mapping must not count")
	}
}

func TestCountKsplicePending(t *testing.T) {
	if got := countKsplicePending("Nothing to be done.\n"); got != 0 {
		t.Errorf("'nothing to be done' = %d, want 0", got)
	}
	if got := countKsplicePending("Your kernel is already up to date.\n"); got != 0 {
		t.Errorf("'up to date' = %d, want 0", got)
	}
	out := "Installing [abc123] CVE-2026-1.\nInstalling [def456] CVE-2026-2.\nDone.\n"
	if got := countKsplicePending(out); got != 2 {
		t.Errorf("two pending = %d, want 2", got)
	}
}

func TestParseMultiversionKernels(t *testing.T) {
	cases := []struct {
		name      string
		conf      string
		policy    string
		unbounded bool
	}{
		{"bounded", "multiversion.kernels = latest,latest-1,running\n", "latest,latest-1,running", false},
		{"all is unbounded", "multiversion.kernels = latest,all\n", "latest,all", true},
		{"absent", "# zypp.conf\nsolver.onlyRequires = true\n", "", false},
		{"commented out", "# multiversion.kernels = all\n", "", false},
		// the `multiversion = provides:...` line must NOT be mistaken for the policy
		{"provides line ignored", "multiversion = provides:multiversion(kernel)\nmultiversion.kernels = latest,running\n", "latest,running", false},
		// prefix matches but no "=" present — Cut's ok=false, the malformed line is skipped
		{"prefix without equals", "multiversion.kernels\nmultiversion.kernels = latest,running\n", "latest,running", false},
	}
	for _, tc := range cases {
		p, u := parseMultiversionKernels(tc.conf)
		if p != tc.policy || u != tc.unbounded {
			t.Errorf("%s: got (%q,%v) want (%q,%v)", tc.name, p, u, tc.policy, tc.unbounded)
		}
	}
}

func TestParseInstallonlyLimit(t *testing.T) {
	if p, u := parseInstallonlyLimit("installonly_limit=3\n"); p != "installonly_limit=3" || u {
		t.Errorf("limit 3 → bounded, got (%q,%v)", p, u)
	}
	if _, u := parseInstallonlyLimit("installonly_limit=0\n"); !u {
		t.Error("limit 0 must be unbounded")
	}
	if p, u := parseInstallonlyLimit("# installonly_limit=0\n"); p != "" || u {
		t.Errorf("commented limit ignored, got (%q,%v)", p, u)
	}
	// prefix matches but no "=" present — Cut's ok=false, the malformed line is skipped
	if p, u := parseInstallonlyLimit("installonly_limit\ninstallonly_limit=5\n"); p != "installonly_limit=5" || u {
		t.Errorf("malformed line without '=' should be skipped, got (%q,%v)", p, u)
	}
}

func TestSnapshotNumberFromPath(t *testing.T) {
	cases := map[string]int{
		// verbatim real openSUSE MicroOS 6.x output:
		"/@/.snapshots/2/snapshot\n":                               2, // findmnt -no FSROOT / (booted)
		"ID 269 gen 43 top level 257 path @/.snapshots/2/snapshot": 2, // btrfs subvolume get-default /
		"@/.snapshots/137/snapshot":                                137,
		"no snapshot here":                                         0,
		".snapshots//snapshot":                                     0, // malformed
		"@/.snapshots/42":                                          0, // marker present but no trailing "/" after the number
	}
	for in, want := range cases {
		if got := snapshotNumberFromPath(in); got != want {
			t.Errorf("snapshotNumberFromPath(%q) = %d, want %d", in, got, want)
		}
	}
}

// ── tuned ────────────────────────────────────────────────────────────────────

func TestTunedAvailable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"tuned-adm": true}, func(b *source.Bundle) {})
	if !TunedAvailable() {
		t.Error("expected TunedAvailable=true when tuned-adm is on PATH")
	}
}

func TestTunedCollector_Collect_HappyPath(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"tuned-adm": true}, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "tuned"}, "active\n", 0)
		b.PutCmd("tuned-adm", []string{"active"}, "Current active profile: virtual-guest\n", 0)
		b.PutCmd("tuned-adm", []string{"recommend"}, "virtual-guest\n", 0)
	})
	c := NewTunedCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.TunedInfo)
	if !info.Available || !info.Active || info.Profile != "virtual-guest" || info.Recommended != "virtual-guest" {
		t.Errorf("unexpected TunedInfo: %+v", info)
	}
	if c.Name() != "Tuned" || c.Timeout() <= 0 {
		t.Errorf("unexpected Name/Timeout: %q/%v", c.Name(), c.Timeout())
	}
}

func TestTunedCollector_Collect_NotAvailable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	c := NewTunedCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if raw.(*models.TunedInfo).Available {
		t.Error("expected Available=false when tuned isn't installed")
	}
}

// ── Kdump / KernelPatch / Ksplice happy-path bodies (gate already covered by
// TestHostKernelCollectorsGateOffInContainer; these exercise the DATA paths) ──

func TestKdumpCollector_Collect_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/lib/systemd/system/kdump.service", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-enabled", "kdump"}, "enabled\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "kdump"}, "active\n", 0)
		b.PutFile("/sys/kernel/kexec_crash_loaded", []byte("1\n"))
		b.PutFile("/sys/kernel/kexec_crash_size", []byte("167772160\n"))
		b.PutFile("/proc/cmdline", []byte("BOOT_IMAGE=/vmlinuz root=/dev/sda1 crashkernel=256M\n"))
	})
	c := NewKdumpCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KdumpInfo)
	if !info.Available || !info.Enabled || !info.ServiceActive || !info.CrashLoaded {
		t.Errorf("expected a fully-active kdump, got %+v", info)
	}
	if info.ReservedBytes != 167772160 || info.Crashkernel != "256M" {
		t.Errorf("expected ReservedBytes/Crashkernel populated, got %+v", info)
	}
}

func TestKernelPatchCollector_Collect_RPMRebootNeeded(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"rpm": true}, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/osrelease", []byte("5.14.0-427.el9.x86_64\n"))
		b.PutCmd("rpm", []string{"-q", "--last", "kernel-uek-core", "kernel-uek", "kernel-core", "kernel"},
			"kernel-core-5.14.0-503.el9.x86_64                            Mon 01 Jun 2026\n"+
				"kernel-core-5.14.0-427.el9.x86_64                            Mon 01 Jan 2026\n", 0)
	})
	c := NewKernelPatchCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KernelPatchInfo)
	if !info.Available || !info.RebootNeeded {
		t.Errorf("expected a newer installed kernel than running to flag RebootNeeded, got %+v", info)
	}
	if info.LatestInstalled != "5.14.0-503.el9.x86_64" {
		t.Errorf("expected LatestInstalled=5.14.0-503.el9.x86_64, got %q", info.LatestInstalled)
	}
}

func TestKernelPatchCollector_Collect_Debian(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/osrelease", []byte("6.1.0-13-amd64\n"))
		b.PutStat("/run/reboot-required", source.FileMeta{})
	})
	c := NewKernelPatchCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KernelPatchInfo)
	if !info.Available || !info.RebootNeeded {
		t.Errorf("expected the Debian reboot-required signal to flag RebootNeeded, got %+v", info)
	}
}

// TestKernelPatchCollector_Collect_RPMSkipsUninstalledFallsBackToSUSE covers
// two branches together: the rpm --last loop skipping "not installed"/"package "
// lines (they never set LatestInstalled), and the zypper SUSE fallback firing
// once no rpm line was usable.
func TestKernelPatchCollector_Collect_RPMSkipsUninstalledFallsBackToSUSE(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"rpm": true, "zypper": true}, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/osrelease", []byte("5.14.0-default\n"))
		b.PutCmd("rpm", []string{"-q", "--last", "kernel-uek-core", "kernel-uek", "kernel-core", "kernel"},
			"package kernel-uek-core is not installed\nkernel-uek is not installed\n", 1)
		b.PutCmd("zypper", []string{"needs-rebooting"}, "", 102)
	})
	c := NewKernelPatchCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KernelPatchInfo)
	if info.LatestInstalled != "" {
		t.Errorf("expected the not-installed/package lines to be skipped, got LatestInstalled=%q", info.LatestInstalled)
	}
	if !info.Available || !info.RebootNeeded {
		t.Errorf("expected the zypper SUSE fallback to report Available+RebootNeeded, got %+v", info)
	}
}

// TestKernelPatchCollector_Collect_NoRecognizedSignal covers the final
// fall-through: rpm present but unusable, no zypper, no Debian reboot-required
// signal — Available stays false rather than a misleading "Kernel OK".
func TestKernelPatchCollector_Collect_NoRecognizedSignal(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"rpm": true}, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/osrelease", []byte("5.14.0-default\n"))
		b.PutCmd("rpm", []string{"-q", "--last", "kernel-uek-core", "kernel-uek", "kernel-core", "kernel"}, "", 1)
	})
	c := NewKernelPatchCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KernelPatchInfo)
	if info.Available {
		t.Errorf("expected Available=false with no recognized kernel-package signal, got %+v", info)
	}
}

func TestKspliceCollector_Collect_Patched(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"uptrack-uname": true}, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/osrelease", []byte("5.4.17-2136.el8uek.x86_64\n"))
		b.PutCmd("uptrack-uname", []string{"-r"}, "5.4.17-2136.301.6.el8uek.x86_64\n", 0)
		b.PutCmd("uptrack-upgrade", []string{"-n"}, "Nothing to be done.\n", 0)
	})
	c := NewKspliceCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KspliceInfo)
	if !info.Available || !info.Patched || info.PendingUpdates != 0 {
		t.Errorf("expected a patched, up-to-date host, got %+v", info)
	}
}

func TestKspliceCollector_Collect_PendingUpdates(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"uptrack-uname": true}, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/osrelease", []byte("5.4.17-2136.el8uek.x86_64\n"))
		b.PutCmd("uptrack-uname", []string{"-r"}, "5.4.17-2136.el8uek.x86_64\n", 0)
		b.PutCmd("uptrack-upgrade", []string{"-n"}, "Installing patch-1\nInstalling patch-2\n", 0)
	})
	c := NewKspliceCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KspliceInfo)
	if info.Patched {
		t.Error("expected Patched=false when effective kernel equals running kernel")
	}
	if info.PendingUpdates != 2 {
		t.Errorf("expected 2 pending updates, got %d", info.PendingUpdates)
	}
}

// TestKspliceCollector_Collect_UpgradeCheckUnverified covers the "uptrack-upgrade
// -n fails with empty stdout" branch: CheckUnverified must be set rather than
// silently reporting PendingUpdates=0 (a false "up to date").
func TestKspliceCollector_Collect_UpgradeCheckUnverified(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"uptrack-uname": true}, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/osrelease", []byte("5.4.17-2136.el8uek.x86_64\n"))
		b.PutCmd("uptrack-uname", []string{"-r"}, "5.4.17-2136.el8uek.x86_64\n", 0)
		b.PutCmd("uptrack-upgrade", []string{"-n"}, "", 1)
	})
	c := NewKspliceCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KspliceInfo)
	if !info.CheckUnverified {
		t.Error("expected CheckUnverified=true when uptrack-upgrade -n fails with empty output")
	}
}

// ── Service restart ──────────────────────────────────────────────────────────

func TestServiceRestartAvailable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dpkg": true}, func(b *source.Bundle) {})
	if !ServiceRestartAvailable() {
		t.Error("expected ServiceRestartAvailable=true when dpkg is present")
	}
}

func TestServiceRestartCollector_Collect_StaleFound(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dpkg": true}, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*/maps", []string{"/proc/123/maps"})
		b.PutFile("/proc/123/maps", []byte(
			"7f0000000000-7f0000010000 r-xp 00000000 08:01 123 /lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n"))
		b.PutFile("/proc/123/comm", []byte("nginx\n"))
	})
	c := NewServiceRestartCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.ServiceRestartInfo)
	if !info.Available || info.StaleCount != 1 || len(info.StaleNames) != 1 || info.StaleNames[0] != "nginx" {
		t.Errorf("expected 1 stale process (nginx) flagged, got %+v", info)
	}
	if c.Name() != "ServiceRestart" || c.Timeout() <= 0 {
		t.Errorf("unexpected Name/Timeout: %q/%v", c.Name(), c.Timeout())
	}
}

func TestServiceRestartCollector_Collect_Clean(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dpkg": true}, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*/maps", []string{"/proc/123/maps"})
		b.PutFile("/proc/123/maps", []byte("7f0000000000-7f0000010000 r-xp 00000000 08:01 123 /lib/libssl.so.3\n"))
	})
	c := NewServiceRestartCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if raw.(*models.ServiceRestartInfo).StaleCount != 0 {
		t.Error("expected no stale processes when no library shows (deleted)")
	}
}

// fakeLookPathPermDeniedSource combines lookPath resolution (as
// fakeLookPathSource does) with a ReadFile permission-denied override for one
// path — needed because ServiceRestartCollector both gates on a package
// manager AND reads /proc/<pid>/maps per process.
type fakeLookPathPermDeniedSource struct {
	*source.Replay
	found      map[string]bool
	deniedPath string
}

func (f fakeLookPathPermDeniedSource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	name := strings.TrimPrefix(key, "lookpath/")
	if f.found[name] {
		return []byte("/usr/bin/" + name), nil
	}
	return nil, errNotFoundCVE
}

func (f fakeLookPathPermDeniedSource) ReadFile(path string) ([]byte, error) {
	if path == f.deniedPath {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	return f.Replay.ReadFile(path)
}

// TestServiceRestartCollector_Collect_PermissionDenied covers the "readFile(mapPath)
// fails with EACCES" branch: another user's /proc/<pid>/maps is unreadable
// non-root, so the scan is partial (NeedsRoot) rather than a clean OK, and the
// denied pid is skipped (not counted as stale).
func TestServiceRestartCollector_Collect_PermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test assumes non-root; running as root in this environment")
	}
	b := source.NewBundle()
	b.PutGlob("/proc/[0-9]*/maps", []string{"/proc/123/maps", "/proc/456/maps"})
	b.PutFile("/proc/456/maps", []byte("7f0000000000-7f0000010000 r-xp 00000000 08:01 123 /lib/libssl.so.3\n"))
	prev := SetSource(fakeLookPathPermDeniedSource{
		Replay:     source.NewReplay(b),
		found:      map[string]bool{"dpkg": true},
		deniedPath: "/proc/123/maps",
	})
	t.Cleanup(func() { SetSource(prev) })
	c := NewServiceRestartCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.ServiceRestartInfo)
	if info.StaleCount != 0 {
		t.Errorf("expected the permission-denied pid to be skipped, got StaleCount=%d", info.StaleCount)
	}
	if !info.NeedsRoot {
		t.Error("expected NeedsRoot=true when another pid's maps is permission-denied while running non-root")
	}
}

// TestServiceRestartCollector_Collect_PermissionDenied_AsRoot covers
// maintenance_linux.go:352-355 — the permission-denied branch and continue
// statement in the maps-file scan. Forces geteuid()==0 via the seam so the
// test is deterministic regardless of whether CI runs as root or non-root.
// With nonRoot=false, NeedsRoot must be false even when deniedOthers is true.
func TestServiceRestartCollector_Collect_PermissionDenied_AsRoot(t *testing.T) {
	swapGeteuid(t, 0)
	b := source.NewBundle()
	b.PutGlob("/proc/[0-9]*/maps", []string{"/proc/789/maps"})
	// /proc/789/maps is NOT seeded in the bundle — fakeLookPathPermDeniedSource
	// intercepts it and returns EPERM before Replay.ReadFile is called.
	prev := SetSource(fakeLookPathPermDeniedSource{
		Replay:     source.NewReplay(b),
		found:      map[string]bool{"dpkg": true},
		deniedPath: "/proc/789/maps",
	})
	t.Cleanup(func() { SetSource(prev) })
	c := NewServiceRestartCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.ServiceRestartInfo)
	// Running as root → nonRoot=false → NeedsRoot = false && deniedOthers
	if info.NeedsRoot {
		t.Error("expected NeedsRoot=false when running as root (nonRoot=false)")
	}
	// The denied pid must not be counted as stale.
	if info.StaleCount != 0 {
		t.Errorf("denied pid must be skipped, got StaleCount=%d", info.StaleCount)
	}
}

// TestServiceRestartCollector_Collect_HidepidRestrictsVisibility covers the
// hidepid=2 gap that EACCES-only detection (deniedOthers) misses: every
// /proc/<pid>/maps entry that IS in the glob results reads cleanly (no
// permission error anywhere), but PID 1 — which always exists on a running
// Linux system — is absent from the results entirely (hidepid=2 omits other
// users' /proc/<pid> directory entries from readdir, no error raised). Must
// still set NeedsRoot, or a hidepid=2 host silently reports a complete scan
// that in fact only ever examined the caller's own processes.
func TestServiceRestartCollector_Collect_HidepidRestrictsVisibility(t *testing.T) {
	swapGeteuid(t, 1000)
	withLookPathFixture(t, map[string]bool{"dpkg": true}, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*/maps", []string{"/proc/123/maps"}) // no /proc/1 — hidepid=2
		b.PutFile("/proc/123/maps", []byte("7f0000000000-7f0000010000 r-xp 00000000 08:01 123 /lib/libssl.so.3\n"))
	})
	c := NewServiceRestartCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.ServiceRestartInfo)
	if !info.NeedsRoot {
		t.Error("expected NeedsRoot=true when PID 1 is absent from the glob results (hidepid=2), even with no read errors")
	}
}

func TestServiceRestartCollector_Collect_NotAvailable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	c := NewServiceRestartCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if raw.(*models.ServiceRestartInfo).Available {
		t.Error("expected Available=false when neither rpm nor dpkg is present")
	}
}

// ── Kernel retention ─────────────────────────────────────────────────────────

// fakeLookPathStatfsSource combines lookPath resolution (as fakeLookPathSource
// does) with a Statfs override for one path — needed because a single
// collector call (KernelRetention) both gates on a package manager AND reads
// /boot's disk usage, and the Bundle API has no public seam for Statfs.
type fakeLookPathStatfsSource struct {
	*source.Replay
	found        map[string]bool
	statfsPath   string
	statfsResult source.StatfsInfo
}

func (f fakeLookPathStatfsSource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	name := strings.TrimPrefix(key, "lookpath/")
	if f.found[name] {
		return []byte("/usr/bin/" + name), nil
	}
	return nil, errNotFoundCVE
}

func (f fakeLookPathStatfsSource) Statfs(path string) (source.StatfsInfo, error) {
	if path == f.statfsPath {
		return f.statfsResult, nil
	}
	return f.Replay.Statfs(path)
}

func TestKernelRetentionAvailable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dpkg": true}, func(b *source.Bundle) {})
	if !KernelRetentionAvailable() {
		t.Error("expected KernelRetentionAvailable=true when dpkg is present")
	}
}

func TestKernelRetentionCollector_Collect_ZypperUnbounded(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/boot/vmlinuz-*", []string{"/boot/vmlinuz-5.14.0-1", "/boot/vmlinuz-5.14.0-2"})
	b.PutFile("/etc/zypp/zypp.conf", []byte("multiversion.kernels = latest,all\n"))
	prev := SetSource(fakeLookPathStatfsSource{
		Replay:       source.NewReplay(b),
		found:        map[string]bool{"zypper": true, "rpm": true}, // KernelRetentionAvailable gates on rpm/dpkg
		statfsPath:   "/boot",
		statfsResult: source.StatfsInfo{Bsize: 4096, Blocks: 250000, Bavail: 12500}, // 95% used
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewKernelRetentionCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KernelRetentionInfo)
	if !info.Available || info.PackageManager != "zypper" || !info.Unbounded {
		t.Errorf("expected zypper+unbounded retention, got %+v", info)
	}
	if info.InstalledKernels != 2 {
		t.Errorf("expected 2 installed kernel images, got %d", info.InstalledKernels)
	}
	if info.BootTotalGB <= 0 || info.BootUsedPct < 90 {
		t.Errorf("expected /boot usage populated from statfs, got %+v", info)
	}
	if c.Name() != "KernelRetention" || c.Timeout() <= 0 {
		t.Errorf("unexpected Name/Timeout: %q/%v", c.Name(), c.Timeout())
	}
}

func TestKernelRetentionCollector_Collect_DNFBounded(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dnf": true, "rpm": true}, func(b *source.Bundle) {
		b.PutGlob("/boot/vmlinuz-*", []string{"/boot/vmlinuz-5.14.0-1"})
		b.PutFile("/etc/dnf/dnf.conf", []byte("installonly_limit=3\n"))
	})
	c := NewKernelRetentionCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KernelRetentionInfo)
	if info.PackageManager != "dnf" || info.Unbounded {
		t.Errorf("expected dnf+bounded retention, got %+v", info)
	}
}

func TestKernelRetentionCollector_Collect_AptNoPolicy(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dpkg": true}, func(b *source.Bundle) {
		b.PutGlob("/boot/vmlinuz-*", []string{"/boot/vmlinuz-5.14.0-1", "/boot/vmlinuz-6.1.0-2"})
	})
	c := NewKernelRetentionCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KernelRetentionInfo)
	if info.PackageManager != "apt" || info.Unbounded {
		t.Errorf("expected apt package manager with no unbounded policy claim, got %+v", info)
	}
	if !info.Available {
		t.Errorf("expected Available=true with kernels + package manager detected, got %+v", info)
	}
}

func TestKernelRetentionCollector_Collect_ContainerGated(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dpkg": true}, func(b *source.Bundle) {
		b.PutGlob("/boot/vmlinuz-*", []string{"/boot/vmlinuz-5.14.0-1"})
	})
	c := NewKernelRetentionCollector(platform.ContainerContext{InContainer: true})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if raw.(*models.KernelRetentionInfo).Available {
		t.Error("expected KernelRetention gated off inside a container")
	}
}

// ── Live patching ────────────────────────────────────────────────────────────

func TestLivePatchAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/kernel/livepatch/*", []string{"/sys/kernel/livepatch/kpatch_1"})
	})
	if !LivePatchAvailable() {
		t.Error("expected LivePatchAvailable=true when a patch dir exists")
	}
}

func TestLivePatchCollector_Collect_MixedStates(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"kpatch": true}, func(b *source.Bundle) {
		b.PutGlob("/sys/kernel/livepatch/*", []string{
			"/sys/kernel/livepatch/patch_enabled",
			"/sys/kernel/livepatch/patch_disabled",
			"/sys/kernel/livepatch/patch_transitioning",
		})
		b.PutFile("/sys/kernel/livepatch/patch_enabled/enabled", []byte("1\n"))
		b.PutFile("/sys/kernel/livepatch/patch_disabled/enabled", []byte("0\n"))
		b.PutFile("/sys/kernel/livepatch/patch_transitioning/enabled", []byte("1\n"))
		b.PutFile("/sys/kernel/livepatch/patch_transitioning/transition", []byte("1\n"))
	})
	c := NewLivePatchCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.LivePatchInfo)
	if info.PatchesLoaded != 3 || info.PatchesEnabled != 2 {
		t.Errorf("expected 3 loaded / 2 enabled, got %+v", info)
	}
	if len(info.DisabledPatches) != 1 || info.DisabledPatches[0] != "patch_disabled" {
		t.Errorf("expected patch_disabled flagged as disabled, got %+v", info.DisabledPatches)
	}
	if len(info.TransitioningPatches) != 1 || info.TransitioningPatches[0] != "patch_transitioning" {
		t.Errorf("expected patch_transitioning flagged, got %+v", info.TransitioningPatches)
	}
	if info.Tool != "kpatch" {
		t.Errorf("expected Tool=kpatch, got %q", info.Tool)
	}
	if c.Name() != "LivePatch" || c.Timeout() <= 0 {
		t.Errorf("unexpected Name/Timeout: %q/%v", c.Name(), c.Timeout())
	}
}

func TestLivePatchCollector_Collect_Unverified(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/kernel/livepatch/*", []string{"/sys/kernel/livepatch/patch_locked"})
		// No file seeded for .../enabled -> ErrNotRecorded, treated as unreadable.
	})
	c := NewLivePatchCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.LivePatchInfo)
	if len(info.UnverifiedPatches) != 1 || info.UnverifiedPatches[0] != "patch_locked" {
		t.Errorf("expected patch_locked flagged as unverified (not disabled), got %+v", info)
	}
}

func TestLivePatchCollector_Collect_KlpTool(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"klp": true}, func(b *source.Bundle) {
		b.PutGlob("/sys/kernel/livepatch/*", []string{"/sys/kernel/livepatch/patch_1"})
		b.PutFile("/sys/kernel/livepatch/patch_1/enabled", []byte("1\n"))
	})
	c := NewLivePatchCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if raw.(*models.LivePatchInfo).Tool != "klp" {
		t.Errorf("expected Tool=klp when klp is on PATH, got %+v", raw)
	}
}

func TestLivePatchCollector_Collect_ContainerGated(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/kernel/livepatch/*", []string{"/sys/kernel/livepatch/patch_1"})
	})
	c := NewLivePatchCollector(platform.ContainerContext{InContainer: true})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if raw.(*models.LivePatchInfo).Available {
		t.Error("expected LivePatch gated off inside a container")
	}
}

// ── Transactional (MicroOS / SLE Micro) ──────────────────────────────────────

func TestIsTransactionalHost(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/transactional-update", source.FileMeta{})
	})
	if !isTransactionalHost() {
		t.Error("expected isTransactionalHost=true when transactional-update exists")
	}
}

func TestTransactionalCollector_Collect_RebootPending(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/transactional-update", source.FileMeta{})
		b.PutCmd("findmnt", []string{"-no", "FSROOT", "/"}, "/@/.snapshots/2/snapshot\n", 0)
		b.PutCmd("btrfs", []string{"subvolume", "get-default", "/"}, "ID 269 gen 45 top level 258 path @/.snapshots/3/snapshot\n", 0)
	})
	c := NewTransactionalCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.TransactionalInfo)
	if !info.Available || !info.RebootPending || info.BootedSnapshot != 2 || info.DefaultSnapshot != 3 {
		t.Errorf("expected RebootPending with booted=2 default=3, got %+v", info)
	}
	if c.Name() != "Transactional" || c.Timeout() <= 0 {
		t.Errorf("unexpected Name/Timeout: %q/%v", c.Name(), c.Timeout())
	}
}

func TestTransactionalCollector_Collect_NoRebootPending(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/transactional-update", source.FileMeta{})
		b.PutCmd("findmnt", []string{"-no", "FSROOT", "/"}, "/@/.snapshots/5/snapshot\n", 0)
		b.PutCmd("btrfs", []string{"subvolume", "get-default", "/"}, "ID 269 gen 45 top level 258 path @/.snapshots/5/snapshot\n", 0)
	})
	c := NewTransactionalCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if raw.(*models.TransactionalInfo).RebootPending {
		t.Error("expected RebootPending=false when booted and default snapshots match")
	}
}

// A failed btrfs read (commonly non-root: `btrfs subvolume get-default`
// needs CAP_SYS_ADMIN) must not leave RebootPending's false zero value
// indistinguishable from a genuinely clean host — Unverified must disclose it.
// Regression for the completeness-guard finding (TestAllChecksRegistered,
// checkExemptions "checkTransactional" before this fix): a staged-but-unbooted
// update on a non-root run used to read as a clean "Transactional: OK".
func TestTransactionalCollector_Collect_UnverifiedOnFailedRead(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/transactional-update", source.FileMeta{})
		b.PutCmd("findmnt", []string{"-no", "FSROOT", "/"}, "/@/.snapshots/2/snapshot\n", 0)
		b.PutCmd("btrfs", []string{"subvolume", "get-default", "/"}, "", 1)
	})
	c := NewTransactionalCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.TransactionalInfo)
	if !info.Unverified {
		t.Errorf("expected Unverified=true when the btrfs read fails, got %+v", info)
	}
	if info.RebootPending {
		t.Errorf("a failed read must not assert RebootPending either way, got %+v", info)
	}
}

func TestTransactionalCollector_Collect_NotAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	c := NewTransactionalCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if raw.(*models.TransactionalInfo).Available {
		t.Error("expected Available=false when transactional-update isn't present")
	}
}
