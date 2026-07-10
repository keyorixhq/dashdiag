//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestCephCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewCephCollector()
	if c.Name() != "Ceph" {
		t.Errorf("Name() = %q, want Ceph", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

func TestIsCephPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/ceph": []byte("/usr/bin/ceph"),
		}, nil, nil)
		if !IsCephPresent() {
			t.Error("expected true when ceph is on PATH")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("ceph", nil)
		})
		if IsCephPresent() {
			t.Error("expected false when ceph is not installed")
		}
	})
}

// TestCephCollector_Collect_HealthFailedNotConfigured guards the "ceph client
// present but no cluster config" branch: `ceph health` failing with no
// /etc/ceph/ceph.conf must stay silent (Configured=false), not flag a fake
// outage on a host that was never part of a cluster.
func TestCephCollector_Collect_HealthFailedNotConfigured(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ceph", []string{"health", "detail", "--format", "json"}, "", 1)
	})
	c := NewCephCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CephInfo)
	if info.Configured {
		t.Errorf("expected Configured=false when /etc/ceph/ceph.conf is absent, got %+v", info)
	}
	if info.Available {
		t.Error("expected Available=false when ceph health failed")
	}
}

// TestCephCollector_Collect_HealthFailedConfiguredUnreachable guards the real
// outage branch: ceph.conf present (this node IS part of a cluster) but
// `ceph health` failed — must be flagged as a real, verified outage, not
// silently degraded.
func TestCephCollector_Collect_HealthFailedConfiguredUnreachable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/ceph/ceph.conf", source.FileMeta{})
		b.PutCmd("ceph", []string{"health", "detail", "--format", "json"}, "", 1)
	})
	c := NewCephCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CephInfo)
	if !info.Configured {
		t.Fatal("expected Configured=true when /etc/ceph/ceph.conf exists")
	}
	if info.StatusReason == "" {
		t.Error("expected a non-empty StatusReason on a configured-but-unreachable cluster")
	}
	// Which sub-branch (plain "unreachable" vs NeedsRoot) fires depends on the
	// real os.Geteuid() with no injectable seam in this file — matches the
	// established pattern in hwraid_linux_test.go/nvme_linux_test.go. Only pin
	// the shared invariant: never a silent healthy verdict.
	if info.Available {
		t.Error("Available = true, want false on a failed health read")
	}
}

// TestCephCollector_Collect_HealthOKBadJSON guards the "ceph health detail
// exited 0 but stdout wasn't parseable health JSON" branch — must mark the
// cluster health unknown, not silently read as clean (Health=="" would match
// neither HEALTH_ERR nor HEALTH_WARN in the verdict).
func TestCephCollector_Collect_HealthOKBadJSON(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ceph", []string{"health", "detail", "--format", "json"}, "not json at all", 0)
		b.PutCmd("ceph", []string{"osd", "stat", "--format", "json"}, "", 1)
	})
	c := NewCephCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CephInfo)
	if !info.Available {
		t.Fatal("Available = false, want true (the command itself succeeded)")
	}
	if info.Health != "HEALTH_UNKNOWN" {
		t.Errorf("Health = %q, want HEALTH_UNKNOWN on unparsable JSON", info.Health)
	}
}

// TestCephCollector_Collect_HappyPath exercises the full success path: valid
// health JSON with checks, plus OSD stat merged in.
func TestCephCollector_Collect_HappyPath(t *testing.T) {
	healthJSON := `{"status":"HEALTH_WARN","checks":{"OSD_DOWN":{"summary":{"message":"1 osds down"}}}}`
	osdJSON := `{"num_osds":3,"num_up_osds":2,"num_in_osds":3}`
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ceph", []string{"health", "detail", "--format", "json"}, healthJSON, 0)
		b.PutCmd("ceph", []string{"osd", "stat", "--format", "json"}, osdJSON, 0)
	})
	c := NewCephCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CephInfo)
	if !info.Available {
		t.Fatal("Available = false, want true")
	}
	if info.Health != "HEALTH_WARN" {
		t.Errorf("Health = %q, want HEALTH_WARN", info.Health)
	}
	if len(info.Summary) != 1 || info.Summary[0] != "1 osds down" {
		t.Errorf("Summary = %v, want [\"1 osds down\"]", info.Summary)
	}
	if info.OSDTotal != 3 || info.OSDUp != 2 || info.OSDIn != 3 {
		t.Errorf("OSD stats = %d/%d/%d, want 3/2/3", info.OSDTotal, info.OSDUp, info.OSDIn)
	}
}

// TestCephCollector_Collect_OSDStatFailedLeavesZero guards that a failed `ceph
// osd stat` doesn't error the whole collector — it just leaves the OSD counts
// at zero while the health data (the primary signal) is still returned.
func TestCephCollector_Collect_OSDStatFailedLeavesZero(t *testing.T) {
	healthJSON := `{"status":"HEALTH_OK","checks":{}}`
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ceph", []string{"health", "detail", "--format", "json"}, healthJSON, 0)
		b.PutCmd("ceph", []string{"osd", "stat", "--format", "json"}, "", 1)
	})
	c := NewCephCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CephInfo)
	if info.Health != "HEALTH_OK" {
		t.Errorf("Health = %q, want HEALTH_OK", info.Health)
	}
	if info.OSDTotal != 0 || info.OSDUp != 0 || info.OSDIn != 0 {
		t.Errorf("expected zero OSD stats when osd stat failed, got %d/%d/%d", info.OSDTotal, info.OSDUp, info.OSDIn)
	}
}
