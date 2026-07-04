//go:build linux

package collectors

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestParseSnapperDate(t *testing.T) {
	// LC_ALL=C format (runCmd's default): "Wed May 13 20:39:27 2026"
	got := parseSnapperDate("Wed May 13 20:39:27 2026")
	if got.IsZero() {
		t.Fatal("a well-formed LC_ALL=C snapper date should parse")
	}
	if got.Year() != 2026 || got.Month() != time.May || got.Day() != 13 {
		t.Errorf("date components wrong: %v", got)
	}

	if got := parseSnapperDate("not a date at all"); !got.IsZero() {
		t.Errorf("a garbled date should return the zero time, got %v", got)
	}
}

func TestParseMiB(t *testing.T) {
	cases := []struct {
		s    string
		want float64
	}{
		{"16.26 MiB", 16.26},
		{"1.00 GiB", 1024},
		{"garbage", 0},
		{"-5.0 MiB", 0}, // negative size is garbled, must not go negative
	}
	for _, c := range cases {
		if got := parseMiB(c.s); got != c.want {
			t.Errorf("parseMiB(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// TestParseSnapperPlain guards the snapshot-count and freshness derivation:
// SnapshotCount excludes header/separator rows, LastSnapshotH reflects the
// most recent dated row, and OldestDays the earliest.
func TestParseSnapperPlain(t *testing.T) {
	recent := time.Now().Add(-2 * time.Hour)
	older := time.Now().Add(-72 * time.Hour)
	// Note: the size token has no space before the unit (1.50MiB) — parseSnapperPlain
	// extracts it via strings.Fields() per line, which would otherwise split
	// "1.50 MiB" into two separate non-matching fields ("1.50" and "MiB").
	out := " # | Type   | Date                              | Description\n" +
		"---+--------+-----------------------------------+-------------\n" +
		"0  | single |                                   | current\n" +
		"1  | single | " + older.Format("Mon Jan 2 15:04:05 2006") + " | 1500.00MiB\n" +
		"2  | single | " + recent.Format("Mon Jan 2 15:04:05 2006") + " | 2500.00MiB\n"

	info := parseSnapperPlain(out, &models.SnapperInfo{})
	if info.SnapshotCount != 3 {
		t.Errorf("expected 3 snapshot rows (header/separator excluded), got %d", info.SnapshotCount)
	}
	if info.LastSnapshotH != 2 {
		t.Errorf("LastSnapshotH should reflect the most recent dated row (~2h ago), got %d", info.LastSnapshotH)
	}
	if info.OldestDays != 3 {
		t.Errorf("OldestDays should reflect the oldest dated row (~72h = 3 days), got %d", info.OldestDays)
	}
	if info.TotalSpaceGB != 3.91 {
		t.Errorf("total space should sum the MiB fields across rows (1500+2500 MiB = 3.91 GB), got %v", info.TotalSpaceGB)
	}
}

func TestParseSnapperPlainNoSnapshots(t *testing.T) {
	info := parseSnapperPlain("", &models.SnapperInfo{})
	if info.SnapshotCount != 0 {
		t.Errorf("empty output should report 0 snapshots, got %d", info.SnapshotCount)
	}
	if info.LastSnapshotH != -1 {
		t.Errorf("no dated snapshot should report LastSnapshotH=-1 (never), got %d", info.LastSnapshotH)
	}
}
