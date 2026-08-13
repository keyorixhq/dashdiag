package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// Golden-output tests for db.go's per-engine renderers (printDBVerdict already
// had coverage from an earlier round). Plain data structs, no live I/O. No
// t.Parallel() (corrupts captureStdout's shared os.Stdout swap).

func TestRoleOrPrimary(t *testing.T) {
	if got := roleOrPrimary(false, 0); got != "primary" {
		t.Errorf("not in recovery should report primary, got %q", got)
	}
	if got := roleOrPrimary(true, 12.7); got != "replica (13s replay lag)" {
		t.Errorf("in recovery should report replica with lag, got %q", got)
	}
}

func TestOrDefault(t *testing.T) {
	if got := orDefault("", "master"); got != "master" {
		t.Errorf("empty string should fall back to default, got %q", got)
	}
	if got := orDefault("slave", "master"); got != "slave" {
		t.Errorf("non-empty string should pass through, got %q", got)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		b    int64
		want string
	}{
		{500, "500 B"},
		{2048, "2 KB"},
		{5 * 1024 * 1024, "5 MB"},
		{2 * 1024 * 1024 * 1024, "2.0 GB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.b); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.b, got, c.want)
		}
	}
}

func TestPrintPostgresState(t *testing.T) {
	if out := captureStdout(t, func() { printPostgresState(&models.PostgresInfo{Detected: false}, output.ModePlain) }); out != "" {
		t.Errorf("an undetected server should print nothing, got:\n%s", out)
	}

	notAccepting := captureStdout(t, func() {
		printPostgresState(&models.PostgresInfo{Detected: true, Accepting: false, AcceptReason: "no response"}, output.ModePlain)
	})
	if !strings.Contains(notAccepting, "NOT accepting") || !strings.Contains(notAccepting, "no response") {
		t.Errorf("a non-accepting server should show the reason, got:\n%s", notAccepting)
	}

	replica := captureStdout(t, func() {
		printPostgresState(&models.PostgresInfo{Detected: true, Accepting: true, MetricsRead: true, InRecovery: true, ReplayLagSec: 5}, output.ModePlain)
	})
	if !strings.Contains(replica, "replica (5s replay lag)") {
		t.Errorf("a replica should show its role and lag, got:\n%s", replica)
	}

	unmeasured := captureStdout(t, func() {
		printPostgresState(&models.PostgresInfo{Detected: true, Accepting: true, MetricsRead: false}, output.ModePlain)
	})
	if !strings.Contains(unmeasured, "metrics unavailable") {
		t.Errorf("unread metrics should say so, not silently omit connection info, got:\n%s", unmeasured)
	}
}

func TestPrintMySQLState(t *testing.T) {
	if out := captureStdout(t, func() { printMySQLState(&models.MySQLInfo{Detected: false}, output.ModePlain) }); out != "" {
		t.Errorf("an undetected server should print nothing, got:\n%s", out)
	}

	mariadb := captureStdout(t, func() {
		printMySQLState(&models.MySQLInfo{Detected: true, Flavor: "MariaDB", MetricsRead: true, IsReplica: true, SecondsBehind: 30}, output.ModePlain)
	})
	if !strings.Contains(mariadb, "MariaDB") || !strings.Contains(mariadb, "30s behind") {
		t.Errorf("a MariaDB replica should show its flavor and lag, got:\n%s", mariadb)
	}

	defaultName := captureStdout(t, func() {
		printMySQLState(&models.MySQLInfo{Detected: true, MetricsRead: true}, output.ModePlain)
	})
	if !strings.Contains(defaultName, "MySQL") || !strings.Contains(defaultName, "Role: primary") {
		t.Errorf("no flavor should default to MySQL and report primary, got:\n%s", defaultName)
	}

	unmeasured := captureStdout(t, func() {
		printMySQLState(&models.MySQLInfo{Detected: true, MetricsRead: false}, output.ModePlain)
	})
	if !strings.Contains(unmeasured, "metrics unavailable") {
		t.Errorf("unread MySQL metrics should say so, got:\n%s", unmeasured)
	}
}

func TestPrintRedisState(t *testing.T) {
	if out := captureStdout(t, func() { printRedisState(&models.RedisInfo{Detected: false}, output.ModePlain) }); out != "" {
		t.Errorf("an undetected server should print nothing, got:\n%s", out)
	}

	withLimit := captureStdout(t, func() {
		printRedisState(&models.RedisInfo{Detected: true, MetricsRead: true, UsedMemoryBytes: 512 * 1024 * 1024, MaxMemoryBytes: 1024 * 1024 * 1024, MaxMemoryPolicy: "allkeys-lru"}, output.ModePlain)
	})
	if !strings.Contains(withLimit, "50%") || !strings.Contains(withLimit, "allkeys-lru") {
		t.Errorf("a memory-limited instance should show its usage percentage and policy, got:\n%s", withLimit)
	}

	noLimit := captureStdout(t, func() {
		printRedisState(&models.RedisInfo{Detected: true, MetricsRead: true, UsedMemoryBytes: 100 * 1024 * 1024}, output.ModePlain)
	})
	if !strings.Contains(noLimit, "no maxmemory limit") {
		t.Errorf("no configured limit should say so rather than divide by zero, got:\n%s", noLimit)
	}

	defaultRole := captureStdout(t, func() {
		printRedisState(&models.RedisInfo{Detected: true, MetricsRead: true}, output.ModePlain)
	})
	if !strings.Contains(defaultRole, "Role: master") {
		t.Errorf("an empty role should default to master, got:\n%s", defaultRole)
	}

	unmeasured := captureStdout(t, func() {
		printRedisState(&models.RedisInfo{Detected: true, MetricsRead: false}, output.ModePlain)
	})
	if !strings.Contains(unmeasured, "metrics unavailable") {
		t.Errorf("unread Redis metrics should say so, got:\n%s", unmeasured)
	}
}

func TestPrintMemcachedState(t *testing.T) {
	if out := captureStdout(t, func() { printMemcachedState(&models.MemcachedInfo{Detected: false}, output.ModePlain) }); out != "" {
		t.Errorf("an undetected server should print nothing, got:\n%s", out)
	}

	withLimit := captureStdout(t, func() {
		printMemcachedState(&models.MemcachedInfo{Detected: true, MetricsRead: true, UsedBytes: 50 * 1024 * 1024, LimitMaxBytes: 100 * 1024 * 1024, CurrItems: 1000, CurrConnections: 5, MaxConnections: 100}, output.ModePlain)
	})
	if !strings.Contains(withLimit, "50%") || !strings.Contains(withLimit, "5/100") {
		t.Errorf("memory usage and connection counts should be shown, got:\n%s", withLimit)
	}

	noStats := captureStdout(t, func() {
		printMemcachedState(&models.MemcachedInfo{Detected: true, MetricsRead: false}, output.ModePlain)
	})
	if !strings.Contains(noStats, "stats unavailable") {
		t.Errorf("unread stats should say so, got:\n%s", noStats)
	}
}

func TestPrintMongoState(t *testing.T) {
	if out := captureStdout(t, func() { printMongoState(&models.MongoDBInfo{Detected: false}, output.ModePlain) }); out != "" {
		t.Errorf("an undetected server should print nothing, got:\n%s", out)
	}

	standalone := captureStdout(t, func() {
		printMongoState(&models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: false}, output.ModePlain)
	})
	if !strings.Contains(standalone, "Standalone") {
		t.Errorf("a non-replica-set instance should say standalone, got:\n%s", standalone)
	}

	// A replica set with no PRIMARY (and a down member) is the classic
	// election-failure/split-brain scenario — must be visible in the output.
	noPrimary := captureStdout(t, func() {
		printMongoState(&models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true,
			ReplicaSetName: "rs0", Members: 3, HasPrimary: false, DownMembers: 1}, output.ModePlain)
	})
	if !strings.Contains(noPrimary, "no PRIMARY") || !strings.Contains(noPrimary, "1 down") {
		t.Errorf("a replica set with no primary and a down member must show both, got:\n%s", noPrimary)
	}

	// The healthy-election counterpart: a replica set WITH a primary elected
	// (HasPrimary=true) must say so, not fall through to the "no PRIMARY" text.
	hasPrimary := captureStdout(t, func() {
		printMongoState(&models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true,
			ReplicaSetName: "rs0", Members: 3, HasPrimary: true}, output.ModePlain)
	})
	if !strings.Contains(hasPrimary, "has PRIMARY") {
		t.Errorf("a replica set with an elected primary should say so, got:\n%s", hasPrimary)
	}

	unmeasured := captureStdout(t, func() {
		printMongoState(&models.MongoDBInfo{Detected: true, MetricsRead: false}, output.ModePlain)
	})
	if !strings.Contains(unmeasured, "metrics unavailable") {
		t.Errorf("unread metrics should say so, got:\n%s", unmeasured)
	}
}

// TestPrintMongoState_SanitizesVersion guards Finding:
// internal-collectors-21-01. m.Version comes straight from the mongo
// shell's db.version() result on the attacker-reachable service at
// 127.0.0.1:27017 — no privilege is required to bind that port before the
// real mongod starts.
func TestPrintMongoState_SanitizesVersion(t *testing.T) {
	out := captureStdout(t, func() {
		printMongoState(&models.MongoDBInfo{Detected: true, MetricsRead: true, Version: "\x1b]0;pwned\x07 6.0"}, output.ModePlain)
	})
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Errorf("MongoDB version output contains a raw control byte, got:\n%q", out)
	}
	if !strings.Contains(out, "6.0") {
		t.Errorf("printable text around the escape sequence must survive sanitization, got:\n%q", out)
	}
}

// TestPrintDBDispatch exercises the type-switch dispatcher itself (each
// printXState function already has direct coverage above).
func TestPrintDBDispatch(t *testing.T) {
	out := captureStdout(t, func() {
		printDB([]runner.Result{
			{Data: &models.PostgresInfo{Detected: true, Accepting: true, MetricsRead: true}},
			{Data: &models.RedisInfo{Detected: true, MetricsRead: true, Role: "master"}},
		}, output.ModePlain)
	})
	if !strings.Contains(out, "PostgreSQL") || !strings.Contains(out, "Redis") {
		t.Errorf("both detected engines should be rendered, got:\n%s", out)
	}
	if !strings.Contains(out, "Databases healthy") {
		t.Errorf("no insights should read healthy, got:\n%s", out)
	}
}

// TestPrintDBDispatchMemcachedMongo covers the remaining two type-switch
// cases in printDB not exercised by TestPrintDBDispatch above.
func TestPrintDBDispatchMemcachedMongo(t *testing.T) {
	out := captureStdout(t, func() {
		printDB([]runner.Result{
			{Data: &models.MemcachedInfo{Detected: true, MetricsRead: true}},
			{Data: &models.MongoDBInfo{Detected: true, MetricsRead: true}},
		}, output.ModePlain)
	})
	if !strings.Contains(out, "Memcached") || !strings.Contains(out, "MongoDB") {
		t.Errorf("both detected engines should be rendered, got:\n%s", out)
	}
}

// TestRunDB exercises runDB's real (read-only) collector-detection wiring.
// This dev container has no local DB engines, so it exercises the
// no-database-detected early-return path — the collector-detected diagnostic
// path is exercised implicitly wherever the CI/dev host does run a DB (the
// gated code itself has no branch logic beyond dispatch, already covered by
// TestPrintDBDispatch above and the per-engine renderer tests).
func TestRunDB(t *testing.T) {
	cmd := newBareCloudCmd()
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runDB(cmd, nil); err != nil {
			t.Fatalf("runDB: %v", err)
		}
	})
	if out == "" {
		t.Error("runDB produced no output")
	}
}
