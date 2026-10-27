package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
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
