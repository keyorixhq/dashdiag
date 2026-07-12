//go:build linux

package collectors

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// postgresSocketDirs are the standard directories a local PostgreSQL server
// places its unix socket in (.s.PGSQL.<port>). Default port 5432.
var postgresSocketDirs = []string{
	"/var/run/postgresql",
	"/run/postgresql",
	"/tmp",
}

// detectPostgresSocket returns the directory of a connectable local Postgres
// socket (default port 5432), or "" if none is reachable. Dialling the socket —
// rather than looking for a client binary — means a host that only has the psql
// client (talking to a remote DB) is correctly treated as having no local server.
func detectPostgresSocket() string {
	for _, dir := range postgresSocketDirs {
		path := dir + "/.s.PGSQL.5432"
		if dialReachable("unix", path, 300*time.Millisecond) {
			return dir
		}
	}
	return ""
}

// PostgresAvailable reports whether a local PostgreSQL server is reachable.
func PostgresAvailable() bool { return detectPostgresSocket() != "" }

// PostgresCollector collects guest-side health for a local PostgreSQL server.
type PostgresCollector struct{}

func NewPostgresCollector() *PostgresCollector { return &PostgresCollector{} }

func (c *PostgresCollector) Name() string           { return "Postgres" }
func (c *PostgresCollector) Timeout() time.Duration { return 6 * time.Second }

func (c *PostgresCollector) Collect(ctx context.Context) (interface{}, error) {
	dir := detectPostgresSocket()
	if dir == "" {
		return &models.PostgresInfo{Detected: false}, nil
	}
	info := &models.PostgresInfo{Detected: true, SocketDir: dir}

	// Liveness — pg_isready needs no authentication. err==nil ⇒ exit 0 ⇒ accepting.
	out, err := runCmd(ctx, "pg_isready", "-h", dir, "-q")
	info.Accepting = err == nil
	if !info.Accepting {
		// Non-quiet for a reason string ("rejecting connections", "no response").
		// pg_isready signals rejecting/no-response purely via a non-zero exit code
		// while still writing the reason to stdout, so runCmdOutput (which keeps
		// stdout on a non-zero exit) is required here — plain runCmd discards it,
		// which left AcceptReason permanently unpopulated in production.
		if r, _ := runCmdOutput(ctx, "pg_isready", "-h", dir); strings.TrimSpace(r) != "" {
			info.AcceptReason = firstLineTrim(r)
		} else if t := strings.TrimSpace(out); t != "" {
			info.AcceptReason = t
		}
	}

	collectPostgresMetrics(ctx, dir, info)
	return info, nil
}

// collectPostgresMetrics fills the metric fields via a single local query. It is
// best-effort: if the query can't run (no peer-auth access), MetricsRead stays
// false and the heuristic reports "couldn't look" rather than a false OK.
func collectPostgresMetrics(ctx context.Context, dir string, info *models.PostgresInfo) {
	// ActiveConns filters to backend_type='client backend' — background workers
	// (checkpointer, walwriter, autovacuum launcher/workers, wal senders) also
	// appear in pg_stat_activity but don't consume a max_connections slot.
	// Counting them systematically overstated the saturation ratio by roughly
	// the number of background processes, which could trip the WARN threshold
	// on a small max_connections even when real client usage was safe.
	// The final column (ReplayCaughtUp) compares last-received vs last-replayed
	// WAL position: equal means the replica has applied everything it has
	// received, even if that happened a while ago because the PRIMARY has been
	// idle — which ReplayLagSec alone can't distinguish from genuinely falling
	// behind. COALESCE to true on a primary (both sides NULL) since the whole
	// replica-lag check is gated on pg_is_in_recovery() anyway.
	const sql = "SELECT current_setting('server_version'), current_setting('max_connections'), " +
		"(SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'), " +
		"(SELECT count(*) FROM pg_stat_activity WHERE state='idle in transaction'), " +
		"pg_is_in_recovery(), " +
		"COALESCE(EXTRACT(EPOCH FROM (now()-pg_last_xact_replay_timestamp())),-1), " +
		"COALESCE(pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn(), true)"

	base := []string{"-X", "-q", "-t", "-A", "-F", "|", "-h", dir, "-U", "postgres", "-d", "postgres", "-c", sql}
	var out string
	var err error
	if geteuid() == 0 {
		// Run as the postgres OS user for peer auth; -n so sudo never blocks on a
		// password prompt (just fails → graceful degrade).
		out, err = runCmd(ctx, "sudo", append([]string{"-n", "-u", "postgres", "--", "psql"}, base...)...)
	} else {
		out, err = runCmd(ctx, "psql", base...)
	}
	if err != nil {
		info.StatusReason = "connection/replication metrics unavailable (need postgres or root access)"
		return
	}
	parsePostgresRow(strings.TrimSpace(out), info)
}

func parsePostgresRow(row string, info *models.PostgresInfo) {
	f := strings.Split(row, "|")
	if len(f) < 7 {
		return
	}
	info.MetricsRead = true
	info.ServerVersion = strings.TrimSpace(f[0])
	info.MaxConnections = atoiSafe(f[1])
	info.ActiveConns = atoiSafe(f[2])
	info.IdleInTxn = atoiSafe(f[3])
	info.InRecovery = strings.TrimSpace(f[4]) == "t"
	if lag, e := strconv.ParseFloat(strings.TrimSpace(f[5]), 64); e == nil && lag >= 0 {
		info.ReplayLagSec = lag
	}
	info.ReplayCaughtUp = strings.TrimSpace(f[6]) == "t"
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func firstLineTrim(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
