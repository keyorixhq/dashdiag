package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// insightWithMsg reports whether any insight at the given level has a message
// containing sub — used to assert on a specific verdict, not just "any WARN".
func insightWithMsg(ins []models.Insight, level, sub string) bool {
	for _, i := range ins {
		if i.Level == level && strings.Contains(i.Message, sub) {
			return true
		}
	}
	return false
}

// TestNICErrorsRecencyGate verifies the NIC hardware-error verdict fires on a high
// error RATE but not on a large cumulative since-boot count that is negligible
// relative to total packets (a stale boot-time blip on a long-lived host).
func TestNICErrorsRecencyGate(t *testing.T) {
	// 5000 errors but across 5 billion packets = 0.0001% — must NOT fire.
	stale := models.NetworkInfo{Interfaces: []models.InterfaceInfo{{
		Name: "eth0", Up: true, RxErrors: 5000, RxPackets: 5_000_000_000,
	}}}
	if got := checkNetwork(stale); insightWithMsg(got, "WARN", "hardware errors") {
		t.Errorf("negligible error rate must not WARN, got %+v", got)
	}

	// 5000 errors across 100k packets = 5% — a real sustained fault, must fire.
	bad := models.NetworkInfo{Interfaces: []models.InterfaceInfo{{
		Name: "eth0", Up: true, RxErrors: 5000, RxPackets: 100_000,
	}}}
	if got := checkNetwork(bad); !insightWithMsg(got, "WARN", "hardware errors") {
		t.Errorf("5%% error rate should WARN, got %+v", got)
	}

	// Below the absolute floor (50 errors) — never fire regardless of rate.
	tiny := models.NetworkInfo{Interfaces: []models.InterfaceInfo{{
		Name: "eth0", Up: true, RxErrors: 50, RxPackets: 100,
	}}}
	if got := checkNetwork(tiny); insightWithMsg(got, "WARN", "hardware errors") {
		t.Errorf("error count below floor must not WARN, got %+v", got)
	}
}

// TestNFSRetransRecencyGate verifies the NFS retransmission verdict gates on the
// retrans RATE (retrans/calls), not a raw since-boot count that never decays.
func TestNFSRetransRecencyGate(t *testing.T) {
	// 500 retrans out of 10M calls = 0.005% — a long-lived client, must NOT fire.
	stale := models.NFSInfo{RpcbindActive: true, RetransPerMin: 500, RPCCalls: 10_000_000}
	if got := checkNFS(stale); insightWithMsg(got, "WARN", "retransmission") {
		t.Errorf("negligible retrans rate must not WARN, got %+v", got)
	}

	// 8000 retrans out of 100k calls = 8% — transport genuinely unreliable, must fire.
	bad := models.NFSInfo{RpcbindActive: true, RetransPerMin: 8000, RPCCalls: 100_000}
	if got := checkNFS(bad); !insightWithMsg(got, "WARN", "retransmission") {
		t.Errorf("8%% retrans rate should WARN, got %+v", got)
	}

	// Below the call-volume floor (a freshly-mounted share) — never fire.
	fresh := models.NFSInfo{RpcbindActive: true, RetransPerMin: 50, RPCCalls: 200}
	if got := checkNFS(fresh); insightWithMsg(got, "WARN", "retransmission") {
		t.Errorf("low call volume must not WARN, got %+v", got)
	}
}
