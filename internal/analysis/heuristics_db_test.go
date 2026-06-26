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

func TestCheckMySQL(t *testing.T) {
	if got := checkMySQL(models.MySQLInfo{Detected: false}); got != nil {
		t.Errorf("undetected mysql should be silent, got %+v", got)
	}

	// Reachable but metrics unreadable → INFO, never a silent OK.
	noMetrics := checkMySQL(models.MySQLInfo{Detected: true, Flavor: "MariaDB", MetricsRead: false})
	if !insightWithMsg(noMetrics, "INFO", "metrics were not read") {
		t.Errorf("unreadable metrics should be INFO, got %+v", noMetrics)
	}

	// Healthy → silent.
	healthy := checkMySQL(models.MySQLInfo{Detected: true, MetricsRead: true, ConnStatsRead: true, MaxConnections: 151, ThreadsConnected: 10})
	if len(healthy) != 0 {
		t.Errorf("healthy mysql should be silent, got %+v", healthy)
	}

	// Metrics read but the connection counters weren't → INFO, never a silent OK.
	noConn := checkMySQL(models.MySQLInfo{Detected: true, MetricsRead: true, ConnStatsRead: false})
	if !insightWithMsg(noConn, "INFO", "connection-saturation was not assessed") {
		t.Errorf("unread connection counters should INFO, got %+v", noConn)
	}

	// Saturation tiers.
	warn := checkMySQL(models.MySQLInfo{Detected: true, MetricsRead: true, ConnStatsRead: true, MaxConnections: 100, ThreadsConnected: 82})
	if !insightWithMsg(warn, "WARN", "approaching the limit") {
		t.Errorf("82%% connections should WARN, got %+v", warn)
	}
	crit := checkMySQL(models.MySQLInfo{Detected: true, MetricsRead: true, ConnStatsRead: true, MaxConnections: 100, ThreadsConnected: 98})
	if !insightWithMsg(crit, "CRIT", "ERROR 1040") {
		t.Errorf("98%% connections should CRIT, got %+v", crit)
	}

	// Replica lag → WARN.
	lag := checkMySQL(models.MySQLInfo{Detected: true, MetricsRead: true, ConnStatsRead: true, MaxConnections: 100, ThreadsConnected: 5, IsReplica: true, SecondsBehind: 700})
	if !insightWithMsg(lag, "WARN", "behind the primary") {
		t.Errorf("replica lag should WARN, got %+v", lag)
	}

	// Replication STOPPED → CRIT (the false-OK fix). Seconds_Behind_Master reads
	// NULL → SecondsBehind 0, so the lag WARN alone would miss it; ReplStopped must
	// fire a CRIT and suppress the (meaningless 0s) lag WARN.
	stopped := checkMySQL(models.MySQLInfo{Detected: true, MetricsRead: true, ConnStatsRead: true, MaxConnections: 100, ThreadsConnected: 5, IsReplica: true, ReplStopped: true, SecondsBehind: 0})
	if !insightWithMsg(stopped, "CRIT", "replication is STOPPED") {
		t.Errorf("stopped replication should CRIT, got %+v", stopped)
	}
	if insightWithMsg(stopped, "WARN", "behind the primary") {
		t.Errorf("stopped replica must not also emit the lag WARN, got %+v", stopped)
	}
}

func TestCheckRedis(t *testing.T) {
	if got := checkRedis(models.RedisInfo{Detected: false}); got != nil {
		t.Errorf("undetected redis should be silent, got %+v", got)
	}

	noMetrics := checkRedis(models.RedisInfo{Detected: true, MetricsRead: false})
	if !insightWithMsg(noMetrics, "INFO", "metrics were not read") {
		t.Errorf("unreadable metrics should be INFO, got %+v", noMetrics)
	}

	// Healthy (no maxmemory limit, low clients, master, save ok) → silent.
	healthy := checkRedis(models.RedisInfo{Detected: true, MetricsRead: true, MaxClientsRead: true, Role: "master", LastSaveKnown: true, LastSaveOK: true})
	if len(healthy) != 0 {
		t.Errorf("healthy redis should be silent, got %+v", healthy)
	}

	// Metrics read but maxclients wasn't → INFO, never a silent OK.
	noMax := checkRedis(models.RedisInfo{Detected: true, MetricsRead: true, MaxClientsRead: false, Role: "master", LastSaveKnown: true, LastSaveOK: true})
	if !insightWithMsg(noMax, "INFO", "client-saturation was not assessed") {
		t.Errorf("unread maxclients should INFO, got %+v", noMax)
	}

	// noeviction at the cliff → CRIT (writes rejected).
	oom := checkRedis(models.RedisInfo{Detected: true, MetricsRead: true, MaxClientsRead: true, MaxMemoryBytes: 1000, UsedMemoryBytes: 980, MaxMemoryPolicy: "noeviction"})
	if !insightWithMsg(oom, "CRIT", "writes will be rejected") {
		t.Errorf("noeviction at 98%% should CRIT, got %+v", oom)
	}
	// eviction policy near limit → WARN, not CRIT.
	evict := checkRedis(models.RedisInfo{Detected: true, MetricsRead: true, MaxClientsRead: true, MaxMemoryBytes: 1000, UsedMemoryBytes: 980, MaxMemoryPolicy: "allkeys-lru"})
	if !insightWithMsg(evict, "WARN", "evicting keys") || insightWithMsg(evict, "CRIT", "") {
		t.Errorf("eviction policy at 98%% should WARN (not CRIT), got %+v", evict)
	}

	// Replica link down → CRIT.
	repl := checkRedis(models.RedisInfo{Detected: true, MetricsRead: true, MaxClientsRead: true, Role: "slave", ReplLinkDown: true})
	if !insightWithMsg(repl, "CRIT", "disconnected from its master") {
		t.Errorf("downed replica link should CRIT, got %+v", repl)
	}

	// Failed save → WARN.
	save := checkRedis(models.RedisInfo{Detected: true, MetricsRead: true, MaxClientsRead: true, Role: "master", LastSaveKnown: true, LastSaveOK: false})
	if !insightWithMsg(save, "WARN", "save failed") {
		t.Errorf("failed RDB save should WARN, got %+v", save)
	}
}
