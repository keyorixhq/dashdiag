//go:build linux

package collectors

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestMTECollectorIdentity guards the static Name/Timeout contract — pure,
// no fixture dependency, safe to run in parallel.
func TestMTECollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewMTECollector()
	if c.Name() != "MTE" {
		t.Errorf("Name() = %q, want MTE", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// TestIsMTEAvailable guards both the arch gate and the /proc/cpuinfo Features
// check. The arch gate itself can't be fixtured (runtime.GOARCH is fixed for
// the test binary), so on a non-arm64 test host we only verify the early
// false; on arm64 we additionally verify the cpuinfo-driven branches.
func TestIsMTEAvailable(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		if IsMTEAvailable() {
			t.Error("expected false on non-arm64 architecture")
		}
		return
	}

	t.Run("mte feature present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/cpuinfo", []byte("processor\t: 0\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh bti mte\n"))
		})
		if !IsMTEAvailable() {
			t.Error("expected true when Features includes mte")
		}
	})

	t.Run("mte feature absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/cpuinfo", []byte("processor\t: 0\nFeatures\t: fp asimd evtstrm aes\n"))
		})
		if IsMTEAvailable() {
			t.Error("expected false when Features omits mte")
		}
	})

	t.Run("cpuinfo unreadable", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {}) // /proc/cpuinfo never seeded
		if IsMTEAvailable() {
			t.Error("expected false when /proc/cpuinfo is unreadable")
		}
	})
}

// TestMTECollector_Collect_ExceptionTraceUnreadable guards the earliest
// early-return: when debug.exception-trace itself can't be read, Available
// stays true (hardware/kernel MTE support is a separate concern) but
// StatusReason explains the gap and no log scan is attempted.
func TestMTECollector_Collect_ExceptionTraceUnreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // /proc/sys/debug/exception-trace never seeded
	c := NewMTECollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MTEInfo)
	if !info.Available {
		t.Error("Available should stay true even when exception-trace is unreadable")
	}
	if info.StatusReason == "" || !strings.Contains(info.StatusReason, "exception-trace") {
		t.Errorf("expected a StatusReason mentioning exception-trace, got %q", info.StatusReason)
	}
	if info.ExceptionTraceEnabled {
		t.Error("ExceptionTraceEnabled should be false when unreadable")
	}
	if info.RecentFaults != nil {
		t.Error("no log scan should occur when exception-trace is unreadable")
	}
}

// TestMTECollector_Collect_ExceptionTraceDisabled guards the "sysctl off"
// short-circuit: a tag-check fault leaves no kernel-log trace while
// exception-trace is 0, so scanning the log would be pointless — Collect
// must return early without invoking journalctl/dmesg at all (no fixture for
// either command is seeded; if Collect tried to run them, runCmd would hit
// ErrNotRecorded and StatusReason would be set, which the assertion below
// catches).
func TestMTECollector_Collect_ExceptionTraceDisabled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/debug/exception-trace", []byte("0\n"))
	})
	c := NewMTECollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MTEInfo)
	if info.ExceptionTraceEnabled {
		t.Error("ExceptionTraceEnabled should be false for sysctl value 0")
	}
	if info.StatusReason != "" {
		t.Errorf("no log scan (and no error) should occur when exception-trace is disabled, got StatusReason=%q", info.StatusReason)
	}
	if info.RecentFaults != nil {
		t.Error("RecentFaults should stay nil when exception-trace is disabled")
	}
}

// TestMTECollector_Collect_JournalctlSucceeds guards the primary path: when
// journalctl -k --grep succeeds, its output is parsed directly and the
// dmesg-fallback 24h recency filter must NOT be applied (usedDmesg stays
// false), so an undated or oddly-dated journalctl line isn't second-guessed.
func TestMTECollector_Collect_JournalctlSucceeds(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/debug/exception-trace", []byte("1\n"))
		b.PutCmd("journalctl",
			[]string{"-k", "--since", "24 hours ago", "--no-pager", "-o", "short-iso", "--grep", "tag check fault"},
			mteJournalOutput, 0)
	})
	c := NewMTECollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MTEInfo)
	if !info.ExceptionTraceEnabled {
		t.Error("ExceptionTraceEnabled should be true for sysctl value 1")
	}
	if len(info.RecentFaults) != 2 {
		t.Fatalf("expected 2 parsed faults from journalctl output, got %d: %+v", len(info.RecentFaults), info.RecentFaults)
	}
}

// TestMTECollector_Collect_DmesgISOFallback guards the first fallback rung:
// journalctl unavailable (non-systemd host), `dmesg --time-format iso`
// succeeds — usedDmesg is true, so the 24h recency filter IS applied, and an
// old fault must be dropped while a recent one survives.
func TestMTECollector_Collect_DmesgISOFallback(t *testing.T) {
	recentLine := time.Now().Add(-1*time.Hour).Format("2006-01-02T15:04:05-0700") +
		" mte_test[42]: unhandled exception: DABT (lower EL), ESR 0x0, synchronous tag check fault in mte_test[abc+1000]\n"
	oldLine := time.Now().Add(-48*time.Hour).Format("2006-01-02T15:04:05-0700") +
		" old_proc[99]: unhandled exception: DABT (lower EL), ESR 0x0, synchronous tag check fault in old_proc[abc+1000]\n"

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/debug/exception-trace", []byte("1\n"))
		b.PutCmdNotFound("journalctl",
			[]string{"-k", "--since", "24 hours ago", "--no-pager", "-o", "short-iso", "--grep", "tag check fault"})
		b.PutCmd("dmesg", []string{"--time-format", "iso"}, recentLine+oldLine, 0)
	})
	c := NewMTECollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MTEInfo)
	if len(info.RecentFaults) != 1 {
		t.Fatalf("expected only the recent fault to survive the dmesg-fallback 24h filter, got %d: %+v", len(info.RecentFaults), info.RecentFaults)
	}
	if info.RecentFaults[0].Process != "mte_test" {
		t.Errorf("expected the recent fault to be mte_test, got %+v", info.RecentFaults[0])
	}
}

// TestMTECollector_Collect_PlainDmesgFallback guards the final fallback rung:
// both journalctl and `dmesg --time-format iso` fail, plain `dmesg` succeeds.
// Undated dmesg lines are boot-relative, so filterMTEFaultsRecent keeps them
// conservatively (zero timestamp = kept).
func TestMTECollector_Collect_PlainDmesgFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/debug/exception-trace", []byte("1\n"))
		b.PutCmdNotFound("journalctl",
			[]string{"-k", "--since", "24 hours ago", "--no-pager", "-o", "short-iso", "--grep", "tag check fault"})
		b.PutCmdNotFound("dmesg", []string{"--time-format", "iso"})
		b.PutCmd("dmesg", nil,
			"[  123.456789] mte_test[7]: unhandled exception: DABT (lower EL), ESR 0x0, synchronous tag check fault in mte_test[abc+1000]\n", 0)
	})
	c := NewMTECollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MTEInfo)
	if len(info.RecentFaults) != 1 {
		t.Fatalf("expected the undated plain-dmesg fault to be kept conservatively, got %d: %+v", len(info.RecentFaults), info.RecentFaults)
	}
}

// TestMTECollector_Collect_AllLogSourcesFail guards the last-resort branch:
// journalctl, dmesg --time-format iso, and plain dmesg all fail — StatusReason
// must explain the total log-read failure and RecentFaults must stay nil
// (never silently report "0 faults" as if a real scan happened).
func TestMTECollector_Collect_AllLogSourcesFail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/debug/exception-trace", []byte("1\n"))
		b.PutCmdNotFound("journalctl",
			[]string{"-k", "--since", "24 hours ago", "--no-pager", "-o", "short-iso", "--grep", "tag check fault"})
		b.PutCmdNotFound("dmesg", []string{"--time-format", "iso"})
		b.PutCmdNotFound("dmesg", nil)
	})
	c := NewMTECollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MTEInfo)
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when all kernel-log sources fail")
	}
	if info.RecentFaults != nil {
		t.Errorf("RecentFaults must stay nil when the log couldn't be scanned, got %+v", info.RecentFaults)
	}
}

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

// TestParseMTETimestamp covers parseMTETimestamp's own boundary branches
// directly — the too-short line and the no-whitespace-token cases the
// parseMTEFaultEvents characterization tests only exercise indirectly via
// well-formed lines.
func TestParseMTETimestamp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
		want bool // whether a non-zero time is expected
	}{
		{"too short (< 19 chars)", "short line", false},
		{"no whitespace, long enough", "2026-05-17T09:12:34+0000-no-space-here-padding", false},
		{"valid short-iso timestamp", "2026-05-17T09:12:34+0000 kernel: tag check fault", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseMTETimestamp(tt.line)
			if got.IsZero() == tt.want {
				t.Errorf("parseMTETimestamp(%q).IsZero() = %v, want IsZero()=%v", tt.line, got.IsZero(), !tt.want)
			}
		})
	}
}
