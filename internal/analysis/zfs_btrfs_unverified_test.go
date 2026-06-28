package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ZFS/btrfs "couldn't read → silent OK" closures (FALSE_OK_SWEEP #21/#22/#23).

func TestZFSListReadFailedIsInfo(t *testing.T) {
	// zpool installed but `zpool list` failed → INFO, not a silent clean.
	if got := checkZFS(models.ZFSInfo{ListReadFailed: true}); !hasLevel(got, "INFO") {
		t.Errorf("ListReadFailed must produce an INFO, got %+v", got)
	}
	// No pools and not failed → genuinely clean.
	if got := checkZFS(models.ZFSInfo{}); len(got) != 0 {
		t.Errorf("no pools + verified must be clean, got %+v", got)
	}
}

func TestZFSStatusReadFailedStandalone(t *testing.T) {
	// An ONLINE pool whose `zpool status` was unread → INFO unverified, and the
	// scrub-age / vdev-error checks must NOT fire on the zero/-1 defaults.
	got := checkZFS(models.ZFSInfo{Pools: []models.ZFSPool{
		{Name: "tank", State: "ONLINE", UsedPct: 10, ScrubAgeDays: -1, StatusReadFailed: true},
	}})
	if !hasLevel(got, "INFO") {
		t.Fatalf("status-unread ONLINE pool must INFO, got %+v", got)
	}
	if hasLevel(got, "WARN") || hasLevel(got, "CRIT") {
		t.Errorf("status-unread pool must not emit WARN/CRIT from zero defaults, got %+v", got)
	}
}

func TestDiskExtrasZFSListReadFailedIsInfo(t *testing.T) {
	got := checkDiskExtras(models.DiskInfo{ZFSListReadFailed: true})
	if !hasInsightMsg(got, "INFO", "could NOT be verified") {
		t.Errorf("disk-path ZFS list-read-failed must INFO 'not verified', got %+v", got)
	}
}

func TestZFSStatusUnreadSkipsScrub(t *testing.T) {
	// A status-unread pool must surface "could not be read" and NOT the false "never
	// been scrubbed" that the -1 default would otherwise trigger. This is now owned by
	// checkZFS (checkZFSPool); checkDiskExtras must NOT also score it (the dedup —
	// otherwise the pool is double-reported).
	pool := models.ZFSPool{Name: "tank", State: "ONLINE", ScrubAgeDays: -1, StatusReadFailed: true}

	got := checkZFSPool(pool)
	if !hasInsightMsg(got, "INFO", "could not be read") {
		t.Errorf("checkZFSPool must surface status unread, got %+v", got)
	}
	if hasInsightMsg(got, "WARN", "never been scrubbed") {
		t.Errorf("must not claim 'never been scrubbed' when status was unread, got %+v", got)
	}

	// checkDiskExtras must stay out of per-pool ZFS scoring (no double-report).
	if d := checkDiskExtras(models.DiskInfo{ZFSPools: []models.ZFSPool{pool}}); len(d) != 0 {
		t.Errorf("checkDiskExtras must not score ZFS pools (deferred to checkZFS), got %+v", d)
	}
}
