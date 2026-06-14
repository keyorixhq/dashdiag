//go:build linux

package collectors

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

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
		events := parseOOMEvents(oomJournalOutput)
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
	})

	t.Run("no OOM events returns empty slice", func(t *testing.T) {
		events := parseOOMEvents(oomEmpty)
		if len(events) != 0 {
			t.Errorf("events = %d, want 0", len(events))
		}
	})

	t.Run("empty input", func(t *testing.T) {
		events := parseOOMEvents("")
		if len(events) != 0 {
			t.Errorf("expected empty, got %d events", len(events))
		}
	})
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
