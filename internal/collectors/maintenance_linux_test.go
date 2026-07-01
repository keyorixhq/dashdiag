//go:build linux

package collectors

import (
	"context"
	"os"
	"syscall"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

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
}

func TestSnapshotNumberFromPath(t *testing.T) {
	cases := map[string]int{
		// verbatim real openSUSE MicroOS 6.x output:
		"/@/.snapshots/2/snapshot\n":                               2, // findmnt -no FSROOT / (booted)
		"ID 269 gen 43 top level 257 path @/.snapshots/2/snapshot": 2, // btrfs subvolume get-default /
		"@/.snapshots/137/snapshot":                                137,
		"no snapshot here":                                         0,
		".snapshots//snapshot":                                     0, // malformed
	}
	for in, want := range cases {
		if got := snapshotNumberFromPath(in); got != want {
			t.Errorf("snapshotNumberFromPath(%q) = %d, want %d", in, got, want)
		}
	}
}
