//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const multipathShowOK = `sdb active LUN01 dm-0
sdc active LUN01 dm-0
sdd active LUN02 dm-1
sde active LUN02 dm-1
`

const multipathShowDegraded = `sdb active LUN01 dm-0
sdc failed LUN01 dm-0
sdd active LUN02 dm-1
sde active LUN02 dm-1
`

const multipathShowAllFailed = `sdb failed LUN01 dm-0
sdc failed LUN01 dm-0
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
}

// Keep strings import used in other tests in this package
var _ = strings.Contains
