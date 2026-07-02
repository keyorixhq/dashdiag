//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestParsePostgresRow(t *testing.T) {
	var info models.PostgresInfo
	parsePostgresRow("14.9|100|5|1|f|-1|t", &info)
	if !info.MetricsRead {
		t.Fatal("MetricsRead should be true")
	}
	if info.ServerVersion != "14.9" || info.MaxConnections != 100 || info.ActiveConns != 5 || info.IdleInTxn != 1 {
		t.Errorf("basic fields mismatch: %+v", info)
	}
	if info.InRecovery {
		t.Error("InRecovery should be false for 'f'")
	}
	if !info.ReplayCaughtUp {
		t.Error("ReplayCaughtUp should be true for 't'")
	}
}

func TestParsePostgresRow_ReplicaNotCaughtUp(t *testing.T) {
	var info models.PostgresInfo
	parsePostgresRow("14.9|100|5|0|t|650|f", &info)
	if !info.InRecovery {
		t.Fatal("InRecovery should be true")
	}
	if info.ReplayCaughtUp {
		t.Error("ReplayCaughtUp should be false for 'f'")
	}
	if info.ReplayLagSec != 650 {
		t.Errorf("ReplayLagSec = %v, want 650", info.ReplayLagSec)
	}
}

// TestParsePostgresRow_TooFewColumns is a regression guard: the row must have
// 7 columns now that ReplayCaughtUp was added — a stale 6-column row (an old
// server, or a malformed reply) must not set MetricsRead or crash.
func TestParsePostgresRow_TooFewColumns(t *testing.T) {
	var info models.PostgresInfo
	parsePostgresRow("14.9|100|5|1|f|-1", &info)
	if info.MetricsRead {
		t.Error("MetricsRead should stay false for a 6-column row")
	}
}
