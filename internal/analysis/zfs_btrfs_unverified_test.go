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

func TestDiskExtrasZFSStatusUnreadSkipsScrub(t *testing.T) {
	// A status-unread pool in the disk path must surface "unread" and NOT the false
	// "never been scrubbed" that the -1 default would otherwise trigger.
	got := checkDiskExtras(models.DiskInfo{ZFSPools: []models.ZFSPool{
		{Name: "tank", State: "ONLINE", ScrubAgeDays: -1, StatusReadFailed: true},
	}})
	if !hasInsightMsg(got, "INFO", "status unread") {
		t.Errorf("expected a 'status unread' INFO, got %+v", got)
	}
	if hasInsightMsg(got, "INFO", "never been scrubbed") {
		t.Errorf("must not claim 'never been scrubbed' when status was unread, got %+v", got)
	}
}
