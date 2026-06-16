//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Fixtures include the column-header row that `multipathd show paths format
// "%d %t %s %m"` actually prints first — omitting it (as the original fixtures did)
// hid a bug where the header was parsed as a phantom failed path.
const multipathShowOK = `dev dm_st  vend/prod/rev     multipath
sdb active LUN01 dm-0
sdc active LUN01 dm-0
sdd active LUN02 dm-1
sde active LUN02 dm-1
`

const multipathShowDegraded = `dev dm_st  vend/prod/rev     multipath
sdb active LUN01 dm-0
sdc failed LUN01 dm-0
sdd active LUN02 dm-1
sde active LUN02 dm-1
`

const multipathShowAllFailed = `dev dm_st  vend/prod/rev     multipath
sdb failed LUN01 dm-0
sdc failed LUN01 dm-0
`

// multipathShowRealHeader is verbatim `multipathd show paths format "%d %t %s %m"`
// output from a live 2-path iSCSI multipath device (LIO target). The header row
// previously became a phantom "multipath" device in state "degraded" → a false CRIT.
const multipathShowRealHeader = `dev dm_st  vend/prod/rev     multipath
sdb active LIO-ORG,disk0,4.0 mpatha
sdc active LIO-ORG,disk0,4.0 mpatha
`

// multipathShowOrphan is VERBATIM `multipathd show paths format "%d %t %s %m"`
// from a real host (MacBookAir4,2, Ubuntu) with multipath-tools installed but NO
// multipath maps. sda is an [orphan] (not multipathed), and its vend/prod/rev
// "ATA,APPLE SSD SM128C" contains SPACES. The old fields[3] map parse read "SSD"
// and the orphan became a phantom "all paths failed" device → false CRIT.
const multipathShowOrphan = `dev dm_st vend/prod/rev        multipath
sda undef ATA,APPLE SSD SM128C [orphan]
`

// multipathShowSpacedVendor is a real multipath device whose vend/prod/rev has a
// SPACE ("ATA,Samsung SSD 870"). The map name must still be read from the last
// field, not fields[3].
const multipathShowSpacedVendor = `dev dm_st vend/prod/rev multipath
sdb active ATA,Samsung SSD 870 mpatha
sdc active ATA,Samsung SSD 870 mpatha
`

func findDevice(devices []models.MultipathDevice, dm string) *models.MultipathDevice {
	for i := range devices {
		if devices[i].DM == dm {
			return &devices[i]
		}
	}
	return nil
}

func TestParseMultipathShow(t *testing.T) {
	t.Run("all paths active", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowOK)
		if len(devices) != 2 {
			t.Fatalf("devices = %d, want 2", len(devices))
		}
		for _, d := range devices {
			if d.FailedPaths != 0 {
				t.Errorf("device %s has %d failed paths, want 0", d.Name, d.FailedPaths)
			}
			if d.State != "active" {
				t.Errorf("device %s state = %q, want active", d.Name, d.State)
			}
		}
	})

	t.Run("one path failed = degraded", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowDegraded)
		dm0 := findDevice(devices, "dm-0")
		if dm0 == nil {
			t.Fatal("dm-0 not found")
		}
		if dm0.FailedPaths != 1 {
			t.Errorf("dm-0 failed paths = %d, want 1", dm0.FailedPaths)
		}
		if dm0.ActivePaths != 1 {
			t.Errorf("dm-0 active paths = %d, want 1", dm0.ActivePaths)
		}
		if dm0.State != "degraded" {
			t.Errorf("dm-0 state = %q, want degraded", dm0.State)
		}
	})

	t.Run("orphan path is not a multipath device", func(t *testing.T) {
		// Real MacBookAir4,2 output: multipath-tools installed, no SAN. The [orphan]
		// sda must yield ZERO devices, not a phantom "all paths failed" CRIT.
		devices := parseMultipathShow(multipathShowOrphan)
		if len(devices) != 0 {
			t.Fatalf("orphan path produced %d device(s), want 0: %+v", len(devices), devices)
		}
	})

	t.Run("spaced vendor still maps to last field", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowSpacedVendor)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1", len(devices))
		}
		if devices[0].DM != "mpatha" {
			t.Errorf("map = %q, want mpatha (vend/prod/rev spaces must not shift it)", devices[0].DM)
		}
		if devices[0].ActivePaths != 2 || devices[0].FailedPaths != 0 {
			t.Errorf("paths active/failed = %d/%d, want 2/0", devices[0].ActivePaths, devices[0].FailedPaths)
		}
	})

	t.Run("all paths failed", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowAllFailed)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1", len(devices))
		}
		if devices[0].ActivePaths != 0 {
			t.Errorf("active paths = %d, want 0", devices[0].ActivePaths)
		}
		if devices[0].State != "degraded" {
			t.Errorf("state = %q, want degraded", devices[0].State)
		}
	})

	// Regression (found via live 2-path iSCSI multipath on a VM): the format header
	// row must not become a phantom "multipath" device that reads as degraded and
	// raises a false CRIT. The real output has exactly ONE healthy device, mpatha.
	t.Run("format header row is not a phantom device", func(t *testing.T) {
		devices := parseMultipathShow(multipathShowRealHeader)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1 (header must be skipped); got %+v", len(devices), devices)
		}
		d := devices[0]
		if d.DM != "mpatha" {
			t.Errorf("device DM = %q, want mpatha", d.DM)
		}
		if d.ActivePaths != 2 || d.FailedPaths != 0 || d.State != "active" {
			t.Errorf("mpatha = {active:%d failed:%d state:%q}, want {2 0 active}", d.ActivePaths, d.FailedPaths, d.State)
		}
	})
}

// Keep strings import used in other tests in this package
var _ = strings.Contains
