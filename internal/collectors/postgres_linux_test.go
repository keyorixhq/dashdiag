//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

const postgresMetricsSQL = "SELECT current_setting('server_version'), current_setting('max_connections'), " +
	"(SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'), " +
	"(SELECT count(*) FROM pg_stat_activity WHERE state='idle in transaction'), " +
	"pg_is_in_recovery(), " +
	"COALESCE(EXTRACT(EPOCH FROM (now()-pg_last_xact_replay_timestamp())),-1), " +
	"COALESCE(pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn(), true)"

func postgresMetricsArgs(dir string) []string {
	return []string{"-X", "-q", "-t", "-A", "-F", "|", "-h", dir, "-U", "postgres", "-d", "postgres", "-c", postgresMetricsSQL}
}

func TestPostgresCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewPostgresCollector()
	if c.Name() != "Postgres" {
		t.Errorf("Name() = %q, want Postgres", c.Name())
	}
	if c.Timeout() != 6*time.Second {
		t.Errorf("Timeout() = %v, want 6s", c.Timeout())
	}
}

func TestDetectPostgresSocket_NotReachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if got := detectPostgresSocket(); got != "" {
		t.Errorf("detectPostgresSocket() = %q, want empty", got)
	}
	if PostgresAvailable() {
		t.Error("PostgresAvailable() = true, want false")
	}
}

func TestDetectPostgresSocket_EachCandidateDir(t *testing.T) {
	for _, dir := range postgresSocketDirs {
		t.Run(dir, func(t *testing.T) {
			withCombinedFixture(t, map[string][]byte{
				"dial/unix/" + dir + "/.s.PGSQL.5432": {'1'},
			}, nil, nil)
			if got := detectPostgresSocket(); got != dir {
				t.Errorf("detectPostgresSocket() = %q, want %q", got, dir)
			}
			if !PostgresAvailable() {
				t.Error("PostgresAvailable() = false, want true")
			}
		})
	}
}

func TestPostgresCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewPostgresCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PostgresInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

// The euid running these tests determines which branch of
// collectPostgresMetrics fires (root -> sudo -u postgres -- psql, non-root ->
// plain psql — see TestCollectPostgresMetrics_NonRootPsqlPath). Both variants
// are seeded so the test passes in either environment (root inside the
// golang:1.26 container, non-root on a typical local run).
func TestPostgresCollector_Collect_FullHappyPath(t *testing.T) {
	const row = "16.3|100|5|0|f|-1|t"
	withCombinedFixture(t, map[string][]byte{
		"dial/unix//var/run/postgresql/.s.PGSQL.5432": {'1'},
	}, nil, func(b *source.Bundle) {
		b.PutCmd("pg_isready", []string{"-h", "/var/run/postgresql", "-q"}, "", 0)
		b.PutCmd("psql", postgresMetricsArgs("/var/run/postgresql"), row, 0)
		b.PutCmd("sudo", append([]string{"-n", "-u", "postgres", "--", "psql"}, postgresMetricsArgs("/var/run/postgresql")...), row, 0)
	})

	c := NewPostgresCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PostgresInfo)
	if !info.Detected || info.SocketDir != "/var/run/postgresql" {
		t.Errorf("info = %+v, want Detected=true SocketDir=/var/run/postgresql", info)
	}
	if !info.Accepting {
		t.Error("Accepting = false, want true")
	}
	if !info.MetricsRead {
		t.Fatal("MetricsRead = false, want true")
	}
	if info.ServerVersion != "16.3" || info.MaxConnections != 100 || info.ActiveConns != 5 || info.IdleInTxn != 0 {
		t.Errorf("info = %+v, want version=16.3 max=100 active=5 idle=0", info)
	}
	if info.InRecovery {
		t.Error("InRecovery = true, want false (primary)")
	}
	if info.ReplayLagSec != 0 {
		t.Errorf("ReplayLagSec = %v, want 0 (unset — negative lag not recorded)", info.ReplayLagSec)
	}
	if !info.ReplayCaughtUp {
		t.Error("ReplayCaughtUp = false, want true")
	}
}

// TestPostgresCollector_Collect_NotAcceptingWithReason guards the
// !info.Accepting path end to end. pg_isready signals "rejecting connections"
// / "no response" / "no attempt" purely via a non-zero exit code while still
// writing the reason to stdout, so the reason-extraction call must use
// runCmdOutput (keeps stdout on non-zero exit), not runCmd (discards it) —
// see the fix in postgres_linux.go.
func TestPostgresCollector_Collect_NotAcceptingWithReason(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/unix//run/postgresql/.s.PGSQL.5432": {'1'},
	}, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("pg_isready", []string{"-h", "/run/postgresql", "-q"})
		b.PutCmd("pg_isready", []string{"-h", "/run/postgresql"}, "/run/postgresql:5432 - rejecting connections\n", 2)
		b.PutCmdNotFound("psql", postgresMetricsArgs("/run/postgresql"))
		b.PutCmdNotFound("sudo", append([]string{"-n", "-u", "postgres", "--", "psql"}, postgresMetricsArgs("/run/postgresql")...))
	})

	c := NewPostgresCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PostgresInfo)
	if info.Accepting {
		t.Error("Accepting = true, want false")
	}
	if info.AcceptReason != "/run/postgresql:5432 - rejecting connections" {
		t.Errorf("AcceptReason = %q, want the pg_isready rejection message", info.AcceptReason)
	}
	if info.MetricsRead {
		t.Error("MetricsRead = true, want false when psql fails")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when metrics could not be collected")
	}
}

// NOTE (found, not fixed — see report): runCmd (postgres_linux.go:56) treats a
// non-zero exit as an error and always returns "" for stdout in that case
// (collector.go's runCmd doc: "returns \"\" ... on a non-zero exit"). That
// means Collect's `out` variable (from the quiet run) is UNCONDITIONALLY ""
// whenever !info.Accepting, so the `else if t := strings.TrimSpace(out); t !=
// ""` fallback at postgres_linux.go:66 can never be true — it is dead code.
// A test exercising it would only prove the dead branch's OWN unreachable
// condition, not real behavior, so it is intentionally omitted; see
// TestPostgresCollector_Collect_NotAcceptingNoReasonAvailable below for the
// reachable "neither source has text" outcome instead.

// TestPostgresCollector_Collect_NotAcceptingNoReasonAvailable guards the
// third outcome: neither the non-quiet nor the quiet pg_isready run produced
// any usable text, so AcceptReason must stay empty rather than panic or
// fabricate a reason.
func TestPostgresCollector_Collect_NotAcceptingNoReasonAvailable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/unix//tmp/.s.PGSQL.5432": {'1'},
	}, nil, func(b *source.Bundle) {
		b.PutCmd("pg_isready", []string{"-h", "/tmp", "-q"}, "", 2)
		b.PutCmd("pg_isready", []string{"-h", "/tmp"}, "", 2)
		b.PutCmdNotFound("psql", postgresMetricsArgs("/tmp"))
		b.PutCmdNotFound("sudo", append([]string{"-n", "-u", "postgres", "--", "psql"}, postgresMetricsArgs("/tmp")...))
	})

	c := NewPostgresCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PostgresInfo)
	if info.Accepting {
		t.Error("Accepting = true, want false")
	}
	if info.AcceptReason != "" {
		t.Errorf("AcceptReason = %q, want empty when neither pg_isready run produced text", info.AcceptReason)
	}
}

func TestAtoiSafe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int
	}{
		{"42", 42},
		{"  7  ", 7},
		{"not-a-number", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := atoiSafe(tt.in); got != tt.want {
			t.Errorf("atoiSafe(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestFirstLineTrim(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"single line", "single line"},
		{"  first line  \nsecond line\n", "first line"},
		{"", ""},
		{"\nsecond\n", ""},
	}
	for _, tt := range tests {
		if got := firstLineTrim(tt.in); got != tt.want {
			t.Errorf("firstLineTrim(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestCollectPostgresMetrics_NonRootPsqlPath directly exercises
// collectPostgresMetrics's non-root branch (plain `psql`, no sudo), forced
// deterministically via the geteuid seam.
func TestCollectPostgresMetrics_NonRootPsqlPath(t *testing.T) {
	swapGeteuid(t, 1000)
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("psql", postgresMetricsArgs("/tmp"), "14.1|50|2|0|f|-1|t", 0)
	})
	info := &models.PostgresInfo{}
	collectPostgresMetrics(context.Background(), "/tmp", info)
	if !info.MetricsRead || info.ServerVersion != "14.1" {
		t.Errorf("info = %+v, want MetricsRead=true ServerVersion=14.1", info)
	}
}

// TestCollectPostgresMetrics_RootSudoPath drives the root branch: `sudo -n -u
// postgres -- psql`, forced deterministically via the geteuid seam (real test
// binaries aren't root, so this branch was previously unreachable in CI
// without it).
func TestCollectPostgresMetrics_RootSudoPath(t *testing.T) {
	swapGeteuid(t, 0)
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("sudo", append([]string{"-n", "-u", "postgres", "--", "psql"}, postgresMetricsArgs("/tmp")...),
			"14.1|50|2|0|f|-1|t", 0)
	})
	info := &models.PostgresInfo{}
	collectPostgresMetrics(context.Background(), "/tmp", info)
	if !info.MetricsRead || info.ServerVersion != "14.1" {
		t.Errorf("info = %+v, want MetricsRead=true ServerVersion=14.1 (via sudo -u postgres)", info)
	}
}

func TestParsePostgresRow(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	var info models.PostgresInfo
	parsePostgresRow("14.9|100|5|1|f|-1", &info)
	if info.MetricsRead {
		t.Error("MetricsRead should stay false for a 6-column row")
	}
}

// TestParsePostgresRow_BadLagValueSkipsButDoesNotCrash guards the lag column's
// ParseFloat failure path: a non-numeric value must leave ReplayLagSec at its
// zero value without panicking or preventing the rest of the row from being
// parsed.
func TestParsePostgresRow_BadLagValueSkipsButDoesNotCrash(t *testing.T) {
	t.Parallel()
	var info models.PostgresInfo
	parsePostgresRow("14.9|100|5|1|f|not-a-number|t", &info)
	if !info.MetricsRead {
		t.Error("MetricsRead should still be true — only the lag column is malformed")
	}
	if info.ReplayLagSec != 0 {
		t.Errorf("ReplayLagSec = %v, want 0 (bad float skipped)", info.ReplayLagSec)
	}
}
