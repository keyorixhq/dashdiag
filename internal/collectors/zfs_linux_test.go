//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestZFSCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewZFSCollector()
	if c.Name() != "ZFS" {
		t.Errorf("Name() = %q, want ZFS", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestIsZFSPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/zpool": []byte("/sbin/zpool"),
		}, nil, nil)
		if !IsZFSPresent() {
			t.Error("expected true when zpool is on PATH")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("zpool", nil)
		})
		if IsZFSPresent() {
			t.Error("expected false when zpool is not installed")
		}
	})
}

// TestZFSCollector_Collect_NotInstalled guards the gate-off path: zpool absent
// must return an empty ZFSInfo{} without attempting `zpool list`/`zpool status`.
func TestZFSCollector_Collect_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("zpool", nil)
	})
	c := NewZFSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ZFSInfo)
	if len(info.Pools) != 0 || info.ListReadFailed {
		t.Errorf("expected empty ZFSInfo{} when zpool absent, got %+v", info)
	}
}

// TestZFSCollector_Collect_ListReadFailed guards the "installed but list
// query failed" branch (commonly permission denied) — must be flagged, not
// silently read as zero pools / clean.
func TestZFSCollector_Collect_ListReadFailed(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/zpool": []byte("/sbin/zpool"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("zpool", []string{"list", "-H", "-o", "name,size,free,frag,cap,health"}, "", 1)
	})
	c := NewZFSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ZFSInfo)
	if !info.ListReadFailed {
		t.Error("expected ListReadFailed=true when zpool list fails")
	}
	if len(info.Pools) != 0 {
		t.Errorf("expected no pools when list read failed, got %+v", info.Pools)
	}
}

// TestZFSCollector_Collect_StatusReadFailed guards the "list succeeded, status
// failed" branch: each pool must be marked StatusReadFailed so the verdict
// treats their (unmerged) zero error counters as unverified, not clean.
func TestZFSCollector_Collect_StatusReadFailed(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/zpool": []byte("/sbin/zpool"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("zpool", []string{"list", "-H", "-o", "name,size,free,frag,cap,health"},
			"tank\t100G\t40G\t23%\t45%\tONLINE\n", 0)
		b.PutCmd("zpool", []string{"status", "-v"}, "", 1)
	})
	c := NewZFSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ZFSInfo)
	if len(info.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %+v", info.Pools)
	}
	if !info.Pools[0].StatusReadFailed {
		t.Errorf("expected StatusReadFailed=true when zpool status fails, got %+v", info.Pools[0])
	}
}

// TestZFSCollector_Collect_HappyPath exercises the full merge of zpool list +
// zpool status output into a single pool record, including vdev error counts,
// a status message, and a scrub line.
func TestZFSCollector_Collect_HappyPath(t *testing.T) {
	statusOut := "  pool: tank\n" +
		" state: ONLINE\n" +
		"status: One or more devices has experienced an error.\n" +
		"  scan: scrub repaired 0B in 00:12:34 with 0 errors on Sun May 12 03:25:01 2024\n" +
		"config:\n\n" +
		"\tNAME        STATE     READ WRITE CKSUM\n" +
		"\ttank        ONLINE       0     0     0\n" +
		"\t  sda       ONLINE       1     0     2\n"

	withCombinedFixture(t, map[string][]byte{
		"lookpath/zpool": []byte("/sbin/zpool"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("zpool", []string{"list", "-H", "-o", "name,size,free,frag,cap,health"},
			"tank\t100G\t40G\t23%\t45%\tONLINE\n", 0)
		b.PutCmd("zpool", []string{"status", "-v"}, statusOut, 0)
	})
	c := NewZFSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ZFSInfo)
	if len(info.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %+v", info.Pools)
	}
	p := info.Pools[0]
	if p.StatusReadFailed {
		t.Error("StatusReadFailed should be false on a successful status read")
	}
	if p.ReadErrors != 1 || p.CksumErrors != 2 {
		t.Errorf("vdev error counts not merged: %+v", p)
	}
	if p.StatusMsg == "" {
		t.Error("expected a non-empty status message")
	}
	if p.ScrubAgeDays < 0 {
		t.Errorf("expected a parsed non-negative scrub age, got %d", p.ScrubAgeDays)
	}
}

// TestMergeZpoolStatus_ScrubVariants guards the three scan-line branches:
// scrub in progress (age=0, healthiest state), none requested (age=-1), and
// state-line override (DEGRADED overriding the list-derived state).
func TestMergeZpoolStatus_ScrubVariants(t *testing.T) {
	t.Run("scrub in progress", func(t *testing.T) {
		pools := map[string]models.ZFSPool{"tank": {Name: "tank", ScrubAgeDays: -1}}
		mergeZpoolStatus("  pool: tank\n  scan: scrub in progress since Mon Jan  1 00:00:00 2024\n", pools)
		if pools["tank"].ScrubAgeDays != 0 {
			t.Errorf("expected ScrubAgeDays=0 for an in-progress scrub, got %d", pools["tank"].ScrubAgeDays)
		}
	})

	t.Run("none requested", func(t *testing.T) {
		pools := map[string]models.ZFSPool{"tank": {Name: "tank", ScrubAgeDays: 5}}
		mergeZpoolStatus("  pool: tank\n  scan: none requested\n", pools)
		if pools["tank"].ScrubAgeDays != -1 {
			t.Errorf("expected ScrubAgeDays=-1 for 'none requested', got %d", pools["tank"].ScrubAgeDays)
		}
	})

	t.Run("state line overrides", func(t *testing.T) {
		pools := map[string]models.ZFSPool{"tank": {Name: "tank", State: "ONLINE"}}
		mergeZpoolStatus("  pool: tank\n  state: DEGRADED\n", pools)
		if pools["tank"].State != "DEGRADED" {
			t.Errorf("expected State=DEGRADED from the status output, got %q", pools["tank"].State)
		}
	})

	t.Run("unknown pool name is skipped", func(t *testing.T) {
		pools := map[string]models.ZFSPool{"tank": {Name: "tank"}}
		mergeZpoolStatus("  pool: other\n  state: DEGRADED\n", pools)
		if pools["tank"].State != "" {
			t.Errorf("a status block for an unlisted pool must not mutate tank, got %+v", pools["tank"])
		}
	})
}

// TestParseZFSVdevErrorLine guards the vdev-line detection: a genuine vdev
// line with a recognized STATE token parses its READ/WRITE/CKSUM columns, a
// non-vdev line (no STATE token) is rejected, and a line with a STATE token
// but garbled counters is rejected without partially parsing.
func TestParseZFSVdevErrorLine(t *testing.T) {
	t.Parallel()
	r, w, c, ok := parseZFSVdevErrorLine("sda ONLINE 1 2 3")
	if !ok || r != 1 || w != 2 || c != 3 {
		t.Errorf("got r=%d w=%d c=%d ok=%v, want 1/2/3/true", r, w, c, ok)
	}

	if _, _, _, ok := parseZFSVdevErrorLine("NAME STATE READ WRITE CKSUM"); ok {
		t.Error("the header line (no STATE token) must not parse as a vdev line")
	}

	if _, _, _, ok := parseZFSVdevErrorLine("sda ONLINE x y z"); ok {
		t.Error("garbled counters after a STATE token must not parse")
	}

	if _, _, _, ok := parseZFSVdevErrorLine("sda ONLINE 1 2"); ok {
		t.Error("too few fields after STATE must not parse")
	}
}

// TestParseZFSCountBoundaries guards the plain-int and K/M/G/T-suffixed
// forms, plus the negative/NaN/Inf/overflow rejection documented at the call
// site (a prior bug let a huge garbled count silently wrap to a negative
// value). Named distinctly from a pre-existing parseZFSCount test elsewhere
// in this package (collision hit during the parallel round-4 coverage push).
func TestParseZFSCountBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    int
		wantOK  bool
		comment string
	}{
		{"42", 42, true, "plain int"},
		{"1K", 1000, true, "K suffix"},
		{"2M", 2000000, true, "M suffix"},
		{"1G", 1000000000, true, "G suffix"},
		{"3T", 3000000000000, true, "T suffix"},
		{"-5", 0, false, "negative plain int rejected"},
		{"abc", 0, false, "unparseable"},
		{"1X", 0, false, "unknown suffix rejected"},
		{"", 0, false, "empty string rejected"},
		{"a", 0, false, "single char, no valid suffix parse"},
	}
	for _, tc := range cases {
		got, ok := parseZFSCount(tc.in)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Errorf("%s: parseZFSCount(%q) = (%d, %v), want (%d, %v)", tc.comment, tc.in, got, ok, tc.want, tc.wantOK)
		}
	}

	// Overflow case documented in the source comment: a huge K-suffixed value
	// must saturate to MaxInt, never wrap negative.
	t.Run("overflow saturates instead of wrapping negative", func(t *testing.T) {
		t.Parallel()
		got, ok := parseZFSCount("10000000000000000K")
		if !ok {
			t.Fatal("expected ok=true (saturated), got false")
		}
		if got < 0 {
			t.Errorf("expected a saturated non-negative count, got %d (the exact false-OK wrap bug this guards against)", got)
		}
	})
}
