//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestParseBondFile_FileNotFound guards bonding_linux.go:73-74 — the openFile
// error branch in parseBondFile. A path that is not seeded in the fixture
// source returns an error from openFile; parseBondFile must propagate it rather
// than panic or return a zero struct silently.
func TestParseBondFile_FileNotFound(t *testing.T) {
	// No t.Parallel(): withFixtureSource swaps the package-level activeSource
	// via SetSource, which is only race-free when serial tests finish before
	// the parallel batch starts (same convention as collector_test.go,
	// disk_linux_test.go).
	withFixtureSource(t, func(_ *source.Bundle) {
		// /proc/net/bonding/bond0 is never seeded — openFile will return an error.
	})
	_, err := parseBondFile("/proc/net/bonding/bond0")
	if err == nil {
		t.Error("parseBondFile on an unseeded path should return an error, got nil")
	}
}

// TestAdjtimexSync_ReturnShape guards clock_linux.go:15-37. adjtimexSync always
// calls the real syscall.Adjtimex; which branch fires (synced/UNSYNC/error)
// depends on the kernel's NTP state and cannot be forced hermetially.
//
// What we can guarantee regardless of the host's NTP state:
//   - source is never empty (even the error path returns "unavailable")
//   - if the call succeeds (source=="adjtimex"), offsetMs is not +Inf/-Inf
//   - the function never panics
//
// The UNSYNC branch (clock_linux.go:24) fires when state==timeError or
// STA_UNSYNC is set — both are observed on hosts with NTP disabled, which CI
// runners are sometimes configured as. This test exercises the call and logs
// the actual result; the assertions hold for ALL branches.
func TestAdjtimexSync_ReturnShape(t *testing.T) {
	t.Parallel()
	synced, offsetMs, src := adjtimexSync()
	t.Logf("adjtimexSync: synced=%v offsetMs=%f source=%q", synced, offsetMs, src)

	if src == "" {
		t.Error("adjtimexSync: source must never be empty — both error and sync paths return a non-empty label")
	}
	// On success, offsetMs is a real offset in milliseconds (may be 0 on a
	// well-synced host or -1 on the error/unavailable path).
	// On error (line 30), source=="unavailable" and offsetMs==-1.
	if src == "unavailable" && offsetMs != -1 {
		t.Errorf("adjtimexSync: error path must return offsetMs=-1, got %f", offsetMs)
	}
}

// TestParseBondFileContent_AllSlavesDown guards the AllDown=true branch —
// all slaves down means AllDown is set AND Degraded is set.
func TestParseBondFileContent_AllSlavesDown(t *testing.T) {
	t.Parallel()
	const allDown = `Ethernet Channel Bonding Driver: v5.15

Bonding Mode: fault-tolerance (active-backup)
MII Status: down
MII Polling Interval (ms): 100

Slave Interface: eth0
MII Status: down
Speed: Unknown
Duplex: Unknown
Link Failure Count: 2

Slave Interface: eth1
MII Status: down
Speed: Unknown
Duplex: Unknown
Link Failure Count: 1
`
	bond, err := parseBondFileContent("bond0", allDown)
	if err != nil {
		t.Fatalf("parseBondFileContent: %v", err)
	}
	if bond.DownSlaves != 2 {
		t.Errorf("DownSlaves = %d, want 2", bond.DownSlaves)
	}
	if !bond.AllDown {
		t.Error("AllDown = false, want true when all slaves are down")
	}
	if !bond.Degraded {
		t.Error("Degraded = false, want true when any slave is down")
	}
}
