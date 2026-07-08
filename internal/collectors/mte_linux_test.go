//go:build linux

package collectors

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Real captured lines from the live QEMU TCG MTE fixture (pve01 arm64mte01,
// Ubuntu 24.04, kernel 6.8.0-124-generic) — see memory
// arm-v85-pac-mte-fixture-gated.md for the full trace.
const mteJournalOutput = `2026-07-08T10:01:32+0000 kernel: mte_test[2263]: unhandled exception: DABT (lower EL), ESR 0x0000000092000051, synchronous tag check fault in mte_test[b847a9c80000+1000]
2026-07-08T10:01:32+0000 kernel: CPU: 1 PID: 2263 Comm: mte_test Not tainted 6.8.0-124-generic #124-Ubuntu
2026-07-08T10:05:10+0000 kernel: other_proc[9001]: unhandled exception: DABT (lower EL), ESR 0x0000000092000061, asynchronous tag check fault in other_proc[aa00bb00+2000]
`

const mteJournalNoise = `2026-07-08T10:00:00+0000 kernel: Linux version 6.8.0-124-generic
2026-07-08T10:00:01+0000 kernel: CPU features: detected: Memory Tagging Extension
`

func TestParseMTEFaultEvents(t *testing.T) {
	t.Parallel()

	t.Run("sync and async faults parsed with process/pid/type", func(t *testing.T) {
		t.Parallel()
		events := parseMTEFaultEvents(mteJournalOutput)
		if len(events) != 2 {
			t.Fatalf("events = %d, want 2", len(events))
		}
		if events[0].Process != "mte_test" || events[0].PID != 2263 || events[0].FaultType != "synchronous" {
			t.Errorf("events[0] = %+v, want mte_test/2263/synchronous", events[0])
		}
		if events[1].Process != "other_proc" || events[1].PID != 9001 || events[1].FaultType != "asynchronous" {
			t.Errorf("events[1] = %+v, want other_proc/9001/asynchronous", events[1])
		}
	})

	t.Run("register-dump continuation line does not double-count", func(t *testing.T) {
		t.Parallel()
		events := parseMTEFaultEvents(mteJournalOutput)
		// The "CPU: 1 PID: 2263 Comm: mte_test..." line must not itself match.
		for _, e := range events {
			if e.PID == 2263 && e.Process != "mte_test" {
				t.Errorf("register-dump line was mis-parsed as a fault: %+v", e)
			}
		}
	})

	t.Run("duplicate fault lines deduplicated by pid+process+type", func(t *testing.T) {
		t.Parallel()
		dup := mteJournalOutput + "2026-07-08T10:01:33+0000 kernel: mte_test[2263]: unhandled exception: DABT (lower EL), ESR 0x0000000092000051, synchronous tag check fault in mte_test[b847a9c80000+1000]\n"
		events := parseMTEFaultEvents(dup)
		if len(events) != 2 {
			t.Errorf("events = %d, want 2 (duplicate line must be deduplicated)", len(events))
		}
	})

	t.Run("noise lines without a tag-check fault are ignored", func(t *testing.T) {
		t.Parallel()
		events := parseMTEFaultEvents(mteJournalNoise)
		if len(events) != 0 {
			t.Errorf("events = %d, want 0 — boot-time 'detected: Memory Tagging Extension' is capability detection, not a fault", len(events))
		}
	})

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		events := parseMTEFaultEvents("")
		if len(events) != 0 {
			t.Errorf("events = %d, want 0", len(events))
		}
	})
}

// TestFilterMTEFaultsRecent mirrors TestFilterOOMRecent: a dated fault older than
// the cutoff is dropped, a recent one kept, an undated one kept (conservative).
func TestFilterMTEFaultsRecent(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	events := []models.MTEFaultEvent{
		{Process: "old", Timestamp: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		{Process: "recent", Timestamp: time.Date(2026, 6, 14, 6, 0, 0, 0, time.UTC)},
		{Process: "undated"},
	}
	got := filterMTEFaultsRecent(events, cutoff)
	if len(got) != 2 {
		t.Fatalf("kept %d events, want 2: %+v", len(got), got)
	}
	for _, e := range got {
		if e.Process == "old" {
			t.Error("a fault older than the 24h cutoff must be dropped")
		}
	}
}
