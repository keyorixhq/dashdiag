//go:build linux

package collectors

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestSnapperCollectorIdentity guards the static Name/Timeout contract and
// that Collect delegates to CollectSnapper — pure identity checks are
// parallel-safe, but Collect touches the fixture source so it must not be.
func TestSnapperCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewSnapperCollector()
	if c.Name() != "Snapshots" {
		t.Errorf("Name() = %q, want Snapshots", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
}

// TestSnapperCollector_Collect_NotInstalled guards the gate-off path: when
// snapper isn't on $PATH, Collect must return an empty, non-error SnapperInfo.
func TestSnapperCollector_Collect_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("snapper", []string{"list-configs"})
	})
	c := NewSnapperCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SnapperInfo)
	if !reflect.DeepEqual(info, &models.SnapperInfo{}) {
		t.Errorf("expected empty SnapperInfo{} when snapper absent, got %+v", info)
	}
}

// TestSnapperCollector_Collect_HappyPath exercises the full delegation:
// lookPath succeeds, list-configs and list both succeed, and the parsed
// result flows back out of SnapperCollector.Collect unchanged.
func TestSnapperCollector_Collect_HappyPath(t *testing.T) {
	// lookPath is Cached-keyed (not a Run), so it must be seeded via the
	// combined-fixture's cached map alongside the snapper Run fixtures.
	withCombinedFixture(t, map[string][]byte{"lookpath/snapper": []byte("/usr/bin/snapper")}, nil, func(b *source.Bundle) {
		b.PutCmd("snapper", []string{"list-configs"}, "Config | Subvolume\n-------+----------\nroot   | /\n", 0)
		b.PutCmd("snapper", []string{"list"},
			" # | Type   | Date                              | Description\n"+
				"---+--------+-----------------------------------+-------------\n"+
				"0  | single |                                   | current\n"+
				"1  | single | "+time.Now().Add(-2*time.Hour).Format("Mon Jan 2 15:04:05 2006")+" | 1500.00MiB\n", 0)
	})
	c := NewSnapperCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SnapperInfo)
	if !info.Available {
		t.Error("expected Available=true when snapper is on $PATH")
	}
	if info.ConfigCount != 1 {
		t.Errorf("expected ConfigCount=1, got %d", info.ConfigCount)
	}
	if info.SnapshotCount != 2 {
		t.Errorf("expected SnapshotCount=2, got %d", info.SnapshotCount)
	}
}

// TestSnapperCollector_Collect_PermissionDenied guards the graceful
// degradation path: snapper is installed but `snapper list` reports "No
// permissions" (non-root) — Collect must set Error, not fail or panic.
func TestSnapperCollector_Collect_PermissionDenied(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/snapper": []byte("/usr/bin/snapper")}, nil, func(b *source.Bundle) {
		b.PutCmd("snapper", []string{"list-configs"}, "Config | Subvolume\n-------+----------\nroot   | /\n", 0)
		b.PutCmd("snapper", []string{"list"}, "No permissions ('root' required)\n", 1)
	})
	c := NewSnapperCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SnapperInfo)
	if info.Error == "" {
		t.Error("expected a non-empty Error when snapper list reports No permissions")
	}
}

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
