package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckPostgres(t *testing.T) {
	// Not detected → silent.
	if got := checkPostgres(models.PostgresInfo{Detected: false}); got != nil {
		t.Errorf("undetected postgres should be silent, got %+v", got)
	}

	// Up but not accepting → CRIT (a live outage).
	notAccepting := checkPostgres(models.PostgresInfo{Detected: true, Accepting: false, AcceptReason: "rejecting connections"})
	if !insightWithMsg(notAccepting, "CRIT", "not accepting connections") {
		t.Errorf("running-but-refusing should CRIT, got %+v", notAccepting)
	}

	// Up + accepting but metrics unreadable → INFO, never a silent OK.
	noMetrics := checkPostgres(models.PostgresInfo{Detected: true, Accepting: true, MetricsRead: false})
	if !insightWithMsg(noMetrics, "INFO", "metrics were not read") {
		t.Errorf("unreadable metrics should be INFO, got %+v", noMetrics)
	}

	// Healthy (accepting, metrics read, low usage) → no insight.
	healthy := checkPostgres(models.PostgresInfo{
		Detected: true, Accepting: true, MetricsRead: true,
		MaxConnections: 100, ActiveConns: 10,
	})
	if len(healthy) != 0 {
		t.Errorf("healthy postgres should be silent, got %+v", healthy)
	}

	// Connection saturation tiers.
	warn := checkPostgres(models.PostgresInfo{Detected: true, Accepting: true, MetricsRead: true, MaxConnections: 100, ActiveConns: 85})
	if !insightWithMsg(warn, "WARN", "approaching the limit") {
		t.Errorf("85%% connections should WARN, got %+v", warn)
	}
	crit := checkPostgres(models.PostgresInfo{Detected: true, Accepting: true, MetricsRead: true, MaxConnections: 100, ActiveConns: 97})
	if !insightWithMsg(crit, "CRIT", "will be refused") {
		t.Errorf("97%% connections should CRIT, got %+v", crit)
	}

	// Idle-in-transaction pileup → WARN.
	idle := checkPostgres(models.PostgresInfo{Detected: true, Accepting: true, MetricsRead: true, MaxConnections: 100, ActiveConns: 5, IdleInTxn: 7})
	if !insightWithMsg(idle, "WARN", "idle in transaction") {
		t.Errorf("idle-in-transaction should WARN, got %+v", idle)
	}

	// Replica lag → WARN.
	lag := checkPostgres(models.PostgresInfo{Detected: true, Accepting: true, MetricsRead: true, MaxConnections: 100, ActiveConns: 5, InRecovery: true, ReplayLagSec: 600})
	if !insightWithMsg(lag, "WARN", "behind the primary") {
		t.Errorf("replica lag should WARN, got %+v", lag)
	}
}
