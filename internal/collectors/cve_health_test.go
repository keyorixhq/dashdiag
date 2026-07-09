package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestCVEHealthCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewCVEHealthCollector()
	if c.Name() != "CVE" {
		t.Errorf("Name() = %q, want CVE", c.Name())
	}
	if c.Timeout() != 130*time.Second {
		t.Errorf("Timeout() = %v, want 130s", c.Timeout())
	}
}

// TestCVEHealthReplayHermetic proves the CVE verdict is frozen into the bundle on
// capture and reproduced verbatim on replay — never re-scanning the replaying
// machine. Whatever the recording host's scan returns, replay must match it.
func TestCVEHealthReplayHermetic(t *testing.T) {
	c := NewCVEHealthCollector()

	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	recorded, err := c.Collect(context.Background())
	SetSource(prev)
	if err != nil {
		t.Fatalf("record collect: %v", err)
	}

	rp := source.NewReplay(rec.Bundle())
	restore := SetSource(rp)
	replayed, err := c.Collect(context.Background())
	SetSource(restore)
	if err != nil {
		t.Fatalf("replay collect: %v", err)
	}

	got := recorded.(*models.CVEAllResult)
	want := replayed.(*models.CVEAllResult)
	if got.PackageManager != want.PackageManager || got.Total != want.Total ||
		got.StatusReason != want.StatusReason ||
		len(got.Critical) != len(want.Critical) || len(got.Important) != len(want.Important) {
		t.Errorf("replay verdict differs from capture:\n  capture=%+v\n  replay =%+v", got, want)
	}
}

// TestCVEHealthReplayMissingIsHonest covers replaying a bundle captured WITHOUT
// --cve-scan: the collector must surface "not captured" rather than fall through
// to a live scan against the (wrong) replaying machine.
func TestCVEHealthReplayMissingIsHonest(t *testing.T) {
	rp := source.NewReplay(source.NewBundle())
	restore := SetSource(rp)
	defer SetSource(restore)

	out, err := NewCVEHealthCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	res := out.(*models.CVEAllResult)
	if !strings.Contains(res.StatusReason, "not captured") {
		t.Errorf("expected a 'not captured' status on a CVE-less bundle, got %q", res.StatusReason)
	}
}
