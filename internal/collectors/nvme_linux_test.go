//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// parseNVMeSmartLog must read `critical_warning` correctly. `nvme smart-log
// --output-format=normal` prints it as %#x (nvme-cli 2.13), so a non-zero
// warning is hex ("0x4"); the old strconv.Atoi path returned 0 for that, hiding
// a failing drive behind heuristics.go's `CriticalWarning > 0` — a false-OK.
func TestParseNVMeCriticalWarningHex(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want int
	}{
		{"zero (plain)", "critical_warning : 0\n", 0},
		{"hex spare-below-threshold bit", "critical_warning : 0x1\n", 1},
		{"hex reliability-degraded bit", "critical_warning : 0x4\n", 4},
		{"hex multiple bits", "critical_warning : 0x1d\n", 0x1d},
		{"decimal still parses", "critical_warning : 4\n", 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var dev models.NVMeDevice
			parseNVMeSmartLog(c.out, &dev)
			if dev.CriticalWarning != c.want {
				t.Errorf("CriticalWarning = %d (0x%x), want %d", dev.CriticalWarning, dev.CriticalWarning, c.want)
			}
		})
	}
}

// applySATASmartJSON must set SmartRead only when smartctl actually reported a
// verdict. `smartctl --json -a` emits JSON with NO smart_status for USB bridges,
// RAID members, and virtual disks — without the SmartRead distinction those
// defaulted SmartOK=false and fired a false "drive may be failing" CRIT.
func TestApplySATASmartJSON(t *testing.T) {
	t.Run("verdict passed", func(t *testing.T) {
		var d models.SATADevice
		applySATASmartJSON(`{"model_name":"X","smart_status":{"passed":true},"temperature":{"current":34}}`, &d)
		if !d.SmartRead || !d.SmartOK || d.TempC != 34 {
			t.Fatalf("got SmartRead=%v SmartOK=%v temp=%d, want true,true,34", d.SmartRead, d.SmartOK, d.TempC)
		}
	})
	t.Run("verdict failed", func(t *testing.T) {
		var d models.SATADevice
		applySATASmartJSON(`{"smart_status":{"passed":false}}`, &d)
		if !d.SmartRead || d.SmartOK {
			t.Fatalf("got SmartRead=%v SmartOK=%v, want true,false", d.SmartRead, d.SmartOK)
		}
	})
	t.Run("no smart_status — unread, no false verdict", func(t *testing.T) {
		var d models.SATADevice
		// Realistic smartctl output for a drive behind a controller: JSON present,
		// no smart_status object.
		applySATASmartJSON(`{"model_name":"VMware Virtual disk","temperature":{"current":0}}`, &d)
		if d.SmartRead {
			t.Fatalf("SmartRead=true with no smart_status — would fire a false CRIT")
		}
	})
	t.Run("garbled JSON — unread", func(t *testing.T) {
		var d models.SATADevice
		applySATASmartJSON(`not json`, &d)
		if d.SmartRead || d.SmartOK {
			t.Fatalf("garbled input produced a verdict: SmartRead=%v SmartOK=%v", d.SmartRead, d.SmartOK)
		}
	})
}

// Negative or garbled counters must not reach a field that a `> 0` / `>= N`
// health check reads — a negative slips under the threshold and reads healthy.
func TestParseNVMeNegativeCountersRejected(t *testing.T) {
	var dev models.NVMeDevice
	parseNVMeSmartLog(
		"media_errors : -5\n"+
			"percentage_used : -3%\n"+
			"unsafe_shutdowns : -1\n"+
			"critical_warning : -2\n",
		&dev)
	if dev.MediaErrors != 0 || dev.PercentageUsed != 0 || dev.UnsafeShutdowns != 0 || dev.CriticalWarning != 0 {
		t.Errorf("negative values leaked: media=%d pct=%d unsafe=%d crit=%d (want all 0)",
			dev.MediaErrors, dev.PercentageUsed, dev.UnsafeShutdowns, dev.CriticalWarning)
	}

	// Valid values still parse.
	var ok models.NVMeDevice
	parseNVMeSmartLog(
		"media_errors : 7\npercentage_used : 12%\nunsafe_shutdowns : 3\npower_on_hours : 1234\n",
		&ok)
	if ok.MediaErrors != 7 || ok.PercentageUsed != 12 || ok.UnsafeShutdowns != 3 || ok.PowerOnHours != 1234 {
		t.Errorf("valid values mis-parsed: media=%d pct=%d unsafe=%d poh=%d",
			ok.MediaErrors, ok.PercentageUsed, ok.UnsafeShutdowns, ok.PowerOnHours)
	}
}
