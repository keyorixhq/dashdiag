//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

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
