package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// DD-COLLECTOR-GAPS-1 Medium items: each "could not look" sentinel must produce an
// Unverified insight naming what was not measured, never silence.
func hasUnverified(insights []models.Insight, substr string) bool {
	for _, ins := range insights {
		if ins.Unverified && strings.Contains(ins.Message, substr) {
			return true
		}
	}
	return false
}

func TestCheckNetwork_InterfacesAndConnectionsUnreadable(t *testing.T) {
	t.Parallel()
	got := checkNetwork(models.NetworkInfo{InterfacesUnreadable: true, ConnectionsUnreadable: true})
	if !hasUnverified(got, "interface list") {
		t.Errorf("no Unverified insight for unreadable interfaces: %+v", got)
	}
	if !hasUnverified(got, "TCP connection table") {
		t.Errorf("no Unverified insight for unreadable connection table: %+v", got)
	}
	for _, ins := range checkNetwork(models.NetworkInfo{}) {
		if ins.Unverified {
			t.Errorf("clean read produced an Unverified insight: %+v", ins)
		}
	}
}

func TestCheckProcesses_RestrictedAndUnreadableListAreUnverified(t *testing.T) {
	t.Parallel()
	th := DefaultThresholds(platform.EnvBareMetal)
	if !hasUnverified(checkProcesses(models.ProcessInfo{ListRestricted: true}, th), "other users") {
		t.Error("no Unverified insight for a hidepid-restricted process list")
	}
	if !hasUnverified(checkProcesses(models.ProcessInfo{ListUnreadable: true}, th), "could not list") {
		t.Error("no Unverified insight for an unreadable process list")
	}
	for _, ins := range checkProcesses(models.ProcessInfo{Total: 100}, th) {
		if ins.Unverified {
			t.Errorf("full listing produced an Unverified insight: %+v", ins)
		}
	}
}

func TestCheckRancher_UnreadableDeploymentsAreUnverified(t *testing.T) {
	t.Parallel()
	got := checkRancher(models.RancherInfo{Available: true, ServerUnreadable: true, WebhookUnreadable: true})
	if !hasUnverified(got, "server deployment") || !hasUnverified(got, "rancher-webhook deployment") {
		t.Errorf("missing Unverified insights for unreadable deployments: %+v", got)
	}
	if len(checkRancher(models.RancherInfo{Available: true, ServerReady: 3, ServerDesired: 3})) != 0 {
		t.Error("healthy Rancher produced insights")
	}
}
