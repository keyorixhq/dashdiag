package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckCloudInit_RecoverableErrorsCapAt3 covers the `i >= 3 { break }` branch
// in checkCloudInit's RecoverableErrors loop — only the first 3 recoverable errors
// must appear in hints even when 4 are present.
func TestCheckCloudInit_RecoverableErrorsCapAt3(t *testing.T) {
	t.Parallel()
	got := checkCloudInit(models.CloudInitInfo{
		Available:         true,
		ExtendedStatus:    "degraded",
		RecoverableErrors: []string{"r1", "r2", "r3", "r4"},
	})
	if len(got) == 0 {
		t.Fatal("degraded cloud-init must produce a WARN insight, got none")
	}
	ins := got[0]
	if ins.Level != "WARN" {
		t.Errorf("expected WARN, got %q", ins.Level)
	}
	// The 4th recoverable error must NOT appear — the loop breaks at i==3.
	count := 0
	for _, h := range ins.Hints {
		for _, r := range []string{"r1", "r2", "r3", "r4"} {
			if h == r {
				count++
			}
		}
	}
	if count != 3 {
		t.Errorf("recoverable-error hints must be capped at 3, got %d in %v", count, ins.Hints)
	}
}

// TestCheckHardware_HealthyClosureReturnTrue covers the `return true` path inside
// the healthy-drive closure in checkHardware. The closure is reached when `out` is
// non-empty but NONE of the existing insights belong to the current drive's prefix.
// Two drives accomplish this: drive 1 (bad SMART) appends a CRIT; drive 2 (good
// SMART) loops the closure with a different prefix — none of out's messages start
// with drive2's prefix, so the closure returns true, healthy emits "OK", and the
// closure's `return true` block is covered.
func TestCheckHardware_HealthyClosureReturnTrue(t *testing.T) {
	t.Parallel()
	got := checkHardware(models.HardwareInfo{
		Drives: []models.HardwareDrive{
			{
				// Drive 1: SMART failed → appends a CRIT with prefix "/dev/sda"
				SmartctlAvailable: true,
				Device:            "/dev/sda",
				SmartRead:         true,
				SmartOK:           false,
			},
			{
				// Drive 2: healthy with a different prefix "/dev/sdb" — the closure
				// iterates out (which has the sda CRIT) but finds no sdb message,
				// so it returns true and an OK insight is emitted.
				SmartctlAvailable: true,
				Device:            "/dev/sdb",
				SmartRead:         true,
				SmartOK:           true,
			},
		},
	})
	if !hasInsightMsg(got, "OK", "/dev/sdb") {
		t.Errorf("healthy second drive must emit an OK insight, got %+v", got)
	}
}
