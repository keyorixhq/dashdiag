package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Fills branch gaps in heuristics_db.go: checkPostgres' default not-accepting
// reason, and checkRedis' 85-95% memory-pressure WARN plus the client-saturation
// WARN branch.

func TestCheckPostgres_NotAcceptingDefaultReason(t *testing.T) {
	t.Parallel()
	pg := models.PostgresInfo{Detected: true, Accepting: false, AcceptReason: ""}
	out := checkPostgres(pg)
	if !hasInsightMsg(out, "CRIT", "not accepting connections") {
		t.Errorf("empty AcceptReason must fall back to the default reason text, got %+v", out)
	}
}

func TestCheckRedis_MemoryApproachingLimit(t *testing.T) {
	t.Parallel()
	r := models.RedisInfo{
		Detected: true, MetricsRead: true,
		MaxMemoryBytes: 1000, UsedMemoryBytes: 880, // 88%
		MaxMemoryPolicy: "allkeys-lru",
	}
	out := checkRedis(r)
	if !hasInsightMsg(out, "WARN", "approaching the limit") {
		t.Errorf("85-95%% memory usage must WARN 'approaching the limit', got %+v", out)
	}
}

func TestCheckRedis_ClientSaturationWarn(t *testing.T) {
	t.Parallel()
	r := models.RedisInfo{
		Detected: true, MetricsRead: true,
		MaxClients: 100, MaxClientsRead: true, ConnectedClients: 95, // 95%
	}
	out := checkRedis(r)
	if !hasInsightMsg(out, "WARN", "clients at 95/100") {
		t.Errorf("client count >=90%% of maxclients must WARN, got %+v", out)
	}
}
