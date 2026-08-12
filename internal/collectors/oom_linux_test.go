//go:build linux

package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewOOMCollector_Identity pins the constructor and identity methods
// (Name/Timeout) — these touch no fixture source, so t.Parallel() is safe.
func TestNewOOMCollector_Identity(t *testing.T) {
	t.Parallel()
	c := NewOOMCollector()
	if c == nil {
		t.Fatal("NewOOMCollector returned nil")
	}
	if got, want := c.Name(), "OOM"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := c.Timeout(), 5*time.Second; got != want {
		t.Errorf("Timeout() = %v, want %v", got, want)
	}
}

const oomJournalOutput = `2026-05-17T09:12:34+0000 kernel: Out of memory: Kill process 12345 (nginx) score 900 or sacrifice child
2026-05-17T09:12:34+0000 kernel: Killed process 12345 (nginx) total-vm:2048kB, anon-rss:1024kB, file-rss:0kB
2026-05-17T09:12:41+0000 kernel: Out of memory: Kill process 23456 (php-fpm) score 750 or sacrifice child
2026-05-17T09:12:41+0000 kernel: Killed process 23456 (php-fpm) total-vm:4096kB, anon-rss:3072kB, file-rss:0kB
2026-05-17T09:15:00+0000 kernel: Out of memory: Kill process 34567 (nginx) score 880 or sacrifice child
`

const oomEmpty = `2026-05-17T09:00:00+0000 kernel: Linux version 6.1.0-generic
2026-05-17T09:00:01+0000 kernel: Command line: BOOT_IMAGE=/vmlinuz
`

func TestParseOOMEvents(t *testing.T) {
	t.Run("multiple OOM events deduplicated by pid", func(t *testing.T) {
		events, truncated := parseOOMEvents(oomJournalOutput)
		// 3 OOM lines but 2 unique PIDs from Kill lines (nginx 12345, php-fpm 23456, nginx 34567)
		if len(events) != 3 {
			t.Errorf("events = %d, want 3", len(events))
		}
		if events[0].Process != "nginx" {
			t.Errorf("events[0].Process = %q, want nginx", events[0].Process)
		}
		if events[0].PID != 12345 {
			t.Errorf("events[0].PID = %d, want 12345", events[0].PID)
		}
		if events[1].Process != "php-fpm" {
			t.Errorf("events[1].Process = %q, want php-fpm", events[1].Process)
		}
		if truncated {
			t.Error("truncated = true, want false — the scanner never errored")
		}
	})

	t.Run("no OOM events returns empty slice", func(t *testing.T) {
		events, truncated := parseOOMEvents(oomEmpty)
		if len(events) != 0 {
			t.Errorf("events = %d, want 0", len(events))
		}
		if truncated {
			t.Error("truncated = true, want false")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		events, truncated := parseOOMEvents("")
		if len(events) != 0 {
			t.Errorf("expected empty, got %d events", len(events))
		}
		if truncated {
			t.Error("truncated = true, want false")
		}
	})
}

// TestParseOOMEvents_ScannerErrorTruncatesButFlagsIt is the regression guard
// for internal-collectors-25-05: a line past bufio.Scanner's default ~64KB
// token limit stops the scan early (Scan returns false on bufio.ErrTooLong),
// silently dropping any OOM events on later lines. The caller must be told
// the scan was incomplete rather than treating a short/empty result as a
// verified, complete count.
func TestParseOOMEvents_ScannerErrorTruncatesButFlagsIt(t *testing.T) {
	oversized := strings.Repeat("x", 128*1024) // exceeds bufio.MaxScanTokenSize's default
	out := "2026-05-17T09:12:34+0000 kernel: Out of memory: Kill process 111 (before) score 900 or sacrifice child\n" +
		oversized + "\n" +
		"2026-05-17T09:12:41+0000 kernel: Out of memory: Kill process 222 (after) score 900 or sacrifice child\n"
	events, truncated := parseOOMEvents(out)
	if !truncated {
		t.Error("truncated = false, want true — the oversized line must trip the scanner's token limit")
	}
	if len(events) != 1 || events[0].Process != "before" {
		t.Errorf("events = %+v, want only the pre-truncation \"before\" event", events)
	}
}

// TestOOMCollector_Collect_AllSourcesUnreadable covers the "neither journalctl
// nor dmesg is readable -> unverified" branch: journalctl, `dmesg --time-format
// iso`, and plain `dmesg` all fail (e.g. kernel.dmesg_restrict=1, non-root),
// so Collect must flag the section unverified rather than silently reporting
// a trustworthy-looking 0 OOM kills.
func TestOOMCollector_Collect_AllSourcesUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"-k", "--since", "24 hours ago",
			"--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process"})
		b.PutCmdNotFound("dmesg", []string{"--time-format", "iso"})
		b.PutCmdNotFound("dmesg", []string{})
	})
	c := NewOOMCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.OOMInfo)
	if !info.Available {
		t.Error("expected Available=true (the section still exists, just unverified)")
	}
	if info.StatusReason == "" {
		t.Error("expected a non-empty StatusReason explaining the kernel log is unreadable")
	}
	if info.EventsLast24h != 0 {
		t.Errorf("EventsLast24h = %d, want 0 when nothing could be read", info.EventsLast24h)
	}
}

// TestOOMCollector_Collect_TruncatesRecentEventsTo5 covers the "len(events) >
// 5 -> keep only the last 5" branch inside Collect.
func TestOOMCollector_Collect_TruncatesRecentEventsTo5(t *testing.T) {
	lines := make([]string, 0, 7)
	for i := range 7 {
		lines = append(lines, fmt.Sprintf(
			"2026-05-17T09:%02d:00+0000 kernel: Out of memory: Kill process %d (app%d) score 900 or sacrifice child",
			i, 10000+i, i))
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-k", "--since", "24 hours ago",
			"--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process"},
			strings.Join(lines, "\n"), 0)
	})
	c := NewOOMCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.OOMInfo)
	if info.EventsLast24h != 7 {
		t.Errorf("EventsLast24h = %d, want 7 (all events counted)", info.EventsLast24h)
	}
	if len(info.RecentEvents) != 5 {
		t.Fatalf("len(RecentEvents) = %d, want 5 (truncated)", len(info.RecentEvents))
	}
	// The kept slice must be the LAST 5 (most recent), i.e. app2..app6.
	if info.RecentEvents[0].Process != "app2" || info.RecentEvents[4].Process != "app6" {
		t.Errorf("RecentEvents = %+v, want the last 5 (app2..app6)", info.RecentEvents)
	}
}

// TestParseOOMTimestamp covers the branches parseOOMEvents' indirect coverage
// (via valid journalctl lines) doesn't reach: a too-short line, a line with no
// whitespace at all (end < 0, token = the whole line), and the happy path
// (both pinned by earlier characterization tests, restated here for
// completeness against the boundary table).
func TestParseOOMTimestamp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
		want bool // whether a non-zero time is expected
	}{
		{"too short (< 19 chars)", "short line", false},
		{"no whitespace at all, but long enough", "2026-05-17T09:12:34+0000-no-space-here-padding", false},
		{"valid short-iso timestamp", "2026-05-17T09:12:34+0000 kernel: Out of memory: Kill process 1 (x)", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseOOMTimestamp(tt.line)
			if got.IsZero() == tt.want {
				t.Errorf("parseOOMTimestamp(%q).IsZero() = %v, want IsZero()=%v", tt.line, got.IsZero(), !tt.want)
			}
		})
	}
}

// TestFilterOOMRecent pins the dmesg-fallback recency window: a dated OOM older than
// the cutoff is dropped, a recent one kept, and an undated one kept (conservative).
func TestFilterOOMRecent(t *testing.T) {
	cutoff := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	events := []models.OOMEvent{
		{Process: "old", Timestamp: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},     // before cutoff → drop
		{Process: "recent", Timestamp: time.Date(2026, 6, 14, 6, 0, 0, 0, time.UTC)}, // after cutoff → keep
		{Process: "undated"}, // zero time → keep
	}
	got := filterOOMRecent(events, cutoff)
	if len(got) != 2 {
		t.Fatalf("kept %d events, want 2: %+v", len(got), got)
	}
	for _, e := range got {
		if e.Process == "old" {
			t.Error("an OOM older than the 24h cutoff must be dropped")
		}
	}
}
