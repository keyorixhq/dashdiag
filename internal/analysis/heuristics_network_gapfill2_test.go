package analysis

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// usbSubsystemSource returns "/sys/bus/usb" for any readlink call on a path
// matching the USB subsystem symlink pattern, so isUSBNetworkInterface returns
// true without needing a real /sys tree.
type usbSubsystemSource struct {
	source.Live
}

func (usbSubsystemSource) Readlink(_ string) (string, error) {
	return "/sys/bus/usb", nil
}

func (usbSubsystemSource) ReadFile(_ string) ([]byte, error) {
	return nil, os.ErrNotExist
}

// TestCheckNetwork_SteamOSWifi covers the net.SteamOSWifi != nil branch in
// checkNetwork (line 339-341). A non-nil SteamOSWifi pointer causes
// checkSteamOSWifi to be called; the result (if any) is appended to out.
func TestCheckNetwork_SteamOSWifiNonNil(t *testing.T) {
	t.Parallel()
	// An empty SteamOSWifi with no anomalies — must not panic. The branch is the
	// target; the SteamOSWifi content is deliberately minimal to avoid coupling
	// this test to checkSteamOSWifi's internal logic.
	net := models.NetworkInfo{
		SteamOSWifi: &models.SteamOSWifi{Backend: "iwd", Connected: true},
	}
	// Must not panic.
	_ = checkNetwork(net)
}

// TestCheckNetwork_SteamOSWifiBothBackends verifies that a BothBackends anomaly
// produces a WARN insight (exercising the non-nil SteamOSWifi branch and a real
// anomaly condition together).
func TestCheckNetwork_SteamOSWifiBothBackends(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{
		SteamOSWifi: &models.SteamOSWifi{Backend: "iwd", BothBackends: true},
	}
	got := checkNetwork(net)
	found := false
	for _, ins := range got {
		if ins.Level == "WARN" || ins.Level == "CRIT" {
			found = true
		}
	}
	if !found {
		t.Errorf("BothBackends anomaly must produce at least one WARN/CRIT, got %+v", got)
	}
}

// TestCheckNetwork_WiFiNoSSID covers the ssid == "" fallback branch (line
// 350-352): when an interface has a WiFi entry with no SSID, the interface name
// is used as the display string instead.
func TestCheckNetwork_WiFiNoSSID(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{
		Interfaces: []models.InterfaceInfo{{
			Name: "wlan0",
			WiFi: &models.WiFiInfo{
				SignalDBm: -85, // < -80 → CRIT
				SSID:      "",  // empty → fall back to interface name
			},
		}},
	}
	got := checkNetwork(net)
	if !hasInsightMsg(got, "CRIT", "wlan0") {
		t.Errorf("WiFi insight with no SSID must use interface name wlan0 in message, got %+v", got)
	}
}

// TestCheckNetwork_BondUSBSlave covers the USB-slave INFO branch in checkNetwork
// (lines 378-391): a healthy (non-degraded, non-all-down) bond whose slave is a
// USB NIC emits an INFO to flag the less-reliable attachment.
// isUSBNetworkInterface reads via ReadlinkViaSource, so we inject a fake source.
func TestCheckNetwork_BondUSBSlave(t *testing.T) {
	// Not parallel: swaps global source state.
	prev := collectors.SetSource(usbSubsystemSource{})
	defer collectors.SetSource(prev)

	net := models.NetworkInfo{
		Bonds: []models.BondInterface{{
			Name:     "bond0",
			Degraded: false,
			AllDown:  false,
			Slaves:   []models.BondSlave{{Name: "eth1"}},
		}},
	}
	got := checkNetwork(net)
	found := false
	for _, ins := range got {
		if ins.Level == "INFO" && strings.Contains(ins.Message, "USB NIC") {
			found = true
		}
	}
	if !found {
		t.Errorf("USB bond slave on healthy bond must emit an INFO about USB NIC, got %+v", got)
	}
}

// TestCheckNetwork_BondDegradedSkipsUSBSlave ensures that a degraded bond does
// NOT emit the USB-slave INFO (the WARN/CRIT is handled by BondingCollector),
// even when source injection would resolve the slave as a USB NIC.
func TestCheckNetwork_BondDegradedSkipsUSBSlave(t *testing.T) {
	// Not parallel: swaps global source state.
	prev := collectors.SetSource(usbSubsystemSource{})
	defer collectors.SetSource(prev)

	net := models.NetworkInfo{
		Bonds: []models.BondInterface{{
			Name:     "bond0",
			Degraded: true,
			Slaves:   []models.BondSlave{{Name: "eth1"}},
		}},
	}
	got := checkNetwork(net)
	for _, ins := range got {
		if ins.Level == "INFO" && strings.Contains(ins.Message, "USB NIC") {
			t.Errorf("degraded bond must not emit USB-slave INFO (handled by BondingCollector), got %q", ins.Message)
		}
	}
}
