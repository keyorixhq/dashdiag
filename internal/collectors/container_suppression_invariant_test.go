package collectors

import (
	"sort"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// This file is the container-vs-host verdict invariant — the systemic guard for
// the "environment-blind suppression" false-OK class: a noise filter that is
// correct in one host shape and wrong in another. That class has bitten in both
// directions — collectors reading host cgroup/CPU paths mis-verdicting INSIDE a
// container (#584/#585), and an unconditional cloud-init unit-failure suppression
// mis-verdicting on a VM (#640, the cloud-config false-OK). The failed-unit
// suppression in systemd.go is where that class concentrates, so it is pinned
// here by two complementary invariants:
//
//  1. TestUnconditionalSuppressionSetIsPinned — the UNCONDITIONAL ignore set
//     (cloudInitUnits) is pinned. Adding a unit must be a deliberate, reviewed
//     act: the unit has to be benign on EVERY host shape (VM, bare metal,
//     container) — i.e. it can never be a genuine failure off-container. If it
//     CAN be a real failure anywhere (as cloud-config can on a VM), it must be
//     gated by host shape (see cloudInitServiceUnits), never suppressed here.
//
//  2. TestContainerSuppressionOnlyRelaxes — the container-conditional suppressors
//     may only RELAX in a container (suppress more, never less), and only for the
//     allowlisted cloudInitServiceUnits. A new container gate that swallows any
//     other unit fails this until the unit is added to the allowlist (review).
//
// Scope: the systemd failed-unit verdict surface. The analysis-layer
// ctrCtx.InContainer gates (slab, container-guest) are a separate, smaller
// surface not covered here.

// cloudInitUnitsPinned is the reviewed contents of the unconditional ignore set.
// Keep in lockstep with cloudInitUnits in systemd.go. CRITERION for membership:
// the unit never represents a genuine failure on a non-container host (it simply
// does not appear failed on a VM / bare metal). A unit that CAN fail for real
// off-container does NOT belong here — gate it by host shape instead.
var cloudInitUnitsPinned = []string{
	"casper-md5check.service",
	"casper.service",
	"console-getty.service",
	"container-getty@.service",
	"dev-hugepages.mount",
	"dev-mqueue.mount",
	"proxmox-regenerate-snakeoil.service",
	"run-lock.mount",
	"ssh@.service",
	"sshd@.service",
	"sys-fs-fuse-connections.mount",
	"sys-kernel-config.mount",
	"sys-kernel-debug.mount",
	"systemd-firstboot.service",
	"systemd-journal-flush.service",
	"systemd-journald-dev-log.socket",
	"systemd-journald.service",
	"systemd-journald.socket",
	"systemd-network-generator.service",
	"systemd-networkd.service",
	"systemd-networkd.socket",
	"systemd-sysctl.service",
	"systemd-sysusers.service",
	"systemd-tmpfiles-clean.service",
	"systemd-tmpfiles-clean.timer",
	"systemd-tmpfiles-setup-dev-early.service",
	"systemd-tmpfiles-setup-dev.service",
	"systemd-tmpfiles-setup.service",
	"systemd-udev-load-credentials.service",
	"tmp.mount",
}

func TestUnconditionalSuppressionSetIsPinned(t *testing.T) {
	t.Parallel()
	got := make([]string, 0, len(cloudInitUnits))
	for k := range cloudInitUnits {
		got = append(got, k)
	}
	sort.Strings(got)
	want := append([]string(nil), cloudInitUnitsPinned...)
	sort.Strings(want)

	gotSet := toSet(got)
	wantSet := toSet(want)
	for _, u := range got {
		if !wantSet[u] {
			t.Errorf("cloudInitUnits gained %q without review.\n"+
				"  This set is suppressed UNCONDITIONALLY (every host shape). Only add a unit\n"+
				"  that can NEVER be a genuine failure off-container. If it can fail for real on\n"+
				"  a VM / bare metal (like cloud-config did, #640), gate it by host shape instead\n"+
				"  (see cloudInitServiceUnits) — do not suppress it here. If it is genuinely\n"+
				"  universal noise, add it to cloudInitUnitsPinned.", u)
		}
	}
	for _, u := range want {
		if !gotSet[u] {
			t.Errorf("cloudInitUnitsPinned lists %q but cloudInitUnits no longer has it — update the pin.", u)
		}
	}
}

// TestContainerSuppressionOnlyRelaxes asserts the two container-conditional
// failed-unit suppressors only ever remove MORE in a container, never fewer, and
// the extra removals are exactly the allowlisted cloud-init services. A genuine
// failure is never suppressed in either mode.
func TestContainerSuppressionOnlyRelaxes(t *testing.T) {
	t.Parallel()
	corpus := []string{
		"my-app.service",                         // genuine failure — must survive both
		"cloud-config.service",                   // gated: surfaces on VM, suppressed in container
		"cloud-final.service",                    // gated
		"cloud-init.service",                     // gated
		"cloud-init-local.service",               // gated
		"console-getty.service",                  // unconditional noise — suppressed both
		"tmp.mount",                              // unconditional noise — suppressed both
		"sshd@0-1.2.3.4:22-5.6.7.8:5000.service", // unconditional (template) — suppressed both
	}

	// []string path (health SystemdCollector).
	hostStr := suppressCloudInitNoise(append([]string(nil), corpus...), false)
	ctrStr := suppressCloudInitNoise(append([]string(nil), corpus...), true)
	assertOnlyRelaxes(t, "suppressCloudInitNoise", hostStr, ctrStr)

	// []models.SystemdUnit path (dsd services deep).
	units := make([]models.SystemdUnit, len(corpus))
	for i, n := range corpus {
		units[i] = models.SystemdUnit{Name: n}
	}
	hostU := unitNames(filterBenignFailedUnits(cloneUnits(units), false))
	ctrU := unitNames(filterBenignFailedUnits(cloneUnits(units), true))
	assertOnlyRelaxes(t, "filterBenignFailedUnits", hostU, ctrU)
}

// assertOnlyRelaxes checks the invariant for one suppressor's host vs container
// output: container ⊆ host; the difference is allowlisted (cloudInitServiceUnits);
// a genuine failure survives both.
func assertOnlyRelaxes(t *testing.T, name string, host, ctr []string) {
	t.Helper()
	hostSet := toSet(host)
	ctrSet := toSet(ctr)

	for _, u := range ctr {
		if !hostSet[u] {
			t.Errorf("%s: container surfaced %q that the host did not — a container gate must only RELAX, never add findings", name, u)
		}
	}
	for _, u := range host {
		if ctrSet[u] {
			continue // present in both — fine
		}
		// Suppressed only in a container → must be in the cloud-init allowlist.
		if !unitIgnored(u, cloudInitServiceUnits) {
			t.Errorf("%s: %q is suppressed only inside a container but is NOT in the cloudInitServiceUnits allowlist.\n"+
				"  Either it is a real failure that should surface everywhere (remove the gate),\n"+
				"  or it is a new container-only-benign unit (add it to cloudInitServiceUnits, with review).", name, u)
		}
	}
	if !toSet(host)["my-app.service"] || !toSet(ctr)["my-app.service"] {
		t.Errorf("%s: a genuine failure (my-app.service) must never be suppressed in either mode", name)
	}
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func cloneUnits(u []models.SystemdUnit) []models.SystemdUnit {
	return append([]models.SystemdUnit(nil), u...)
}

func unitNames(u []models.SystemdUnit) []string {
	out := make([]string, len(u))
	for i := range u {
		out[i] = u[i].Name
	}
	return out
}
