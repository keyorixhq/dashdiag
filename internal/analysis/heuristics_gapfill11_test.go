package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestK8sEventInsight_UnequalCounts covers the `return ordered[i].count > ordered[j].count`
// branch inside the sort.Slice comparator in k8sEventInsight. That branch only fires
// when two reasons have DIFFERENT occurrence counts; tests that use one-of-each
// distinct reasons always fall through to the alphabetical tiebreak and leave it uncovered.
func TestK8sEventInsight_UnequalCounts(t *testing.T) {
	t.Parallel()
	events := []models.K8sEvent{
		{Reason: "BackOff", Age: "30s"},
		{Reason: "BackOff", Age: "31s"},
		{Reason: "BackOff", Age: "32s"},   // count=3
		{Reason: "Unhealthy", Age: "30s"}, // count=1
	}
	ins := k8sEventInsight("WARN", events)
	if ins.Level != "WARN" {
		t.Errorf("expected WARN, got %q", ins.Level)
	}
	// Highest-count reason (BackOff×3) must appear first in the summary.
	if !strings.Contains(ins.Message, "BackOff×3") {
		t.Errorf("most-frequent reason must be in summary, got %q", ins.Message)
	}
}

// TestCheckBonding_USBSlaveHealthyBond covers the `isUSBNetworkInterface(s.Name)` true
// body inside checkBonding's healthy-bond path (DownSlaves==0, lines 607-617). That
// call reads /sys/class/net/<iface>/device/subsystem via ReadlinkViaSource; we inject a
// fake source that returns "/sys/bus/usb" for any readlink call so the check fires
// without needing a real /sys tree.
// Not parallel: swaps the global source.
func TestCheckBonding_USBSlaveHealthyBond(t *testing.T) {
	prev := collectors.SetSource(usbSubsystemSource{})
	defer collectors.SetSource(prev)

	b := models.BondingInfo{Bonds: []models.BondInterface{{
		Name:       "bond0",
		DownSlaves: 0,
		Slaves: []models.BondSlave{
			{Name: "eth0", State: "up"},
			{Name: "eth1", State: "up"},
		},
	}}}
	got := checkBonding(b)
	found := false
	for _, ins := range got {
		if ins.Level == "INFO" && strings.Contains(ins.Message, "USB NIC") {
			found = true
		}
	}
	if !found {
		t.Errorf("healthy bond with USB slave must emit INFO about USB NIC, got %+v", got)
	}
}
