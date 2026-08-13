//go:build linux

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// mysqlSocketPaths are the standard unix-socket locations for a local MySQL /
// MariaDB server across distros.
var mysqlSocketPaths = []string{
	"/var/run/mysqld/mysqld.sock",
	"/run/mysqld/mysqld.sock",
	"/var/lib/mysql/mysql.sock",
	"/tmp/mysql.sock",
}

// detectMySQLSocket returns a connectable local MySQL/MariaDB socket path, or ""
// — dialling the socket (not just finding a client binary) so a host with only
// the mysql client talking to a remote DB is correctly seen as no local server.
func detectMySQLSocket() string {
	for _, path := range mysqlSocketPaths {
		if dialReachable("unix", path, 300*time.Millisecond) {
			return path
		}
	}
	return ""
}

// MySQLAvailable reports whether a local MySQL/MariaDB server is reachable.
func MySQLAvailable() bool { return detectMySQLSocket() != "" }

// MySQLCollector collects guest-side health for a local MySQL/MariaDB server.
type MySQLCollector struct{}

func NewMySQLCollector() *MySQLCollector { return &MySQLCollector{} }

func (c *MySQLCollector) Name() string           { return "MySQL" }
func (c *MySQLCollector) Timeout() time.Duration { return 6 * time.Second }

func (c *MySQLCollector) Collect(ctx context.Context) (interface{}, error) {
	sock := detectMySQLSocket()
	if sock == "" {
		return &models.MySQLInfo{Detected: false}, nil
	}
	info := &models.MySQLInfo{Detected: true, SocketPath: sock, Accepting: true}

	// Verify the socket is actually owned by root or the mysql/mariadb service
	// account before running a client against it — a predictable path (one
	// candidate is /tmp/mysql.sock) can be pre-created by an unprivileged local
	// attacker, whose impostor listener could feed collectMySQLMetrics
	// fabricated output. See socketpeer_linux.go for why SO_PEERCRED (kernel-
	// verified, unspoofable by the peer) is the sound check here.
	trusted, verified := socketPeerTrusted(sock, "mysql")
	info.PeerVerified = verified
	info.PeerTrusted = trusted
	if !verified {
		info.StatusReason = "socket peer identity could not be verified — skipping metrics rather than trusting an unverified listener"
		return info, nil
	}
	if !trusted {
		info.StatusReason = "socket present but not owned by root or the mysql service account — refusing to query a possible impostor listener"
		return info, nil
	}

	collectMySQLMetrics(ctx, sock, info)
	return info, nil
}

// collectMySQLMetrics fills the metric fields via the mysql client (socket auth
// as the current OS user — root maps to root@localhost via the unix_socket
// plugin on modern installs). Best-effort: on access failure MetricsRead stays
// false and the heuristic reports "couldn't look" rather than a false OK.
func collectMySQLMetrics(ctx context.Context, sock string, info *models.MySQLInfo) {
	q := func(sql string) (string, bool) {
		out, err := runCmd(ctx, "mysql", "--socket="+sock, "-N", "-B", "-e", sql)
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(out), true
	}

	ver, ok := q("SELECT VERSION()")
	if !ok {
		info.StatusReason = "connection/replication metrics unavailable (need root or a socket-auth account)"
		return
	}
	info.MetricsRead = true
	info.Version = ver
	if strings.Contains(strings.ToLower(ver), "mariadb") {
		info.Flavor = "MariaDB"
	} else {
		info.Flavor = "MySQL"
	}
	maxOK := false
	if v, ok := q("SELECT @@max_connections"); ok {
		info.MaxConnections = atoiSafe(v)
		maxOK = true
	}
	// SHOW GLOBAL STATUS rows are "Name\tValue" (portable across MySQL/MariaDB).
	threadsOK := false
	if v, ok := q("SHOW GLOBAL STATUS LIKE 'Threads_connected'"); ok {
		info.ThreadsConnected = atoiSafe(lastField(v))
		threadsOK = true
	}
	// Both numbers are needed for the saturation ratio; only claim it's assessable
	// when both queries actually returned.
	info.ConnStatsRead = maxOK && threadsOK
	parseMySQLReplica(q, info)
}

// parseMySQLReplica reads replica status and records replica lag. Empty output
// ⇒ not a replica. MySQL 8.4 REMOVED "SHOW SLAVE STATUS" entirely in favor of
// "SHOW REPLICA STATUS" (MariaDB and MySQL ≤8.3 still only understand the old
// form) — try the old statement first and fall back to the new one, so a
// stopped or badly-lagging 8.4+ replica isn't silently read as "not a replica"
// just because the removed statement errored.
func parseMySQLReplica(q func(string) (string, bool), info *models.MySQLInfo) {
	out, ok := q("SHOW SLAVE STATUS\\G")
	if !ok || strings.TrimSpace(out) == "" {
		out, ok = q("SHOW REPLICA STATUS\\G")
		if !ok || strings.TrimSpace(out) == "" {
			return
		}
	}
	info.IsReplica = true
	ioRunning, sqlRunning := true, true // assume running unless a "not Yes" is seen
	for _, line := range strings.Split(out, "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		key, val := strings.TrimSpace(k), strings.TrimSpace(v)
		switch key {
		// Seconds_Behind_Master on MariaDB / MySQL ≤8.3; Seconds_Behind_Source is
		// the MySQL 8.4+ renaming.
		case "Seconds_Behind_Master", "Seconds_Behind_Source":
			// NULL means replication is not running — handled via the thread states
			// below, which is the authoritative signal.
			if val != "" && val != "NULL" {
				info.SecondsBehind = atoiSafe(val)
			}
		// Slave_* on MariaDB / MySQL ≤8.3 (SHOW SLAVE STATUS); Replica_* is the
		// MySQL 8.4+ renaming — accept both so a stopped thread is caught on either.
		case "Slave_IO_Running", "Replica_IO_Running":
			ioRunning = strings.EqualFold(val, "Yes")
		case "Slave_SQL_Running", "Replica_SQL_Running":
			sqlRunning = strings.EqualFold(val, "Yes")
		}
	}
	info.ReplStopped = !ioRunning || !sqlRunning
}

// lastField returns the last whitespace-separated field of s (the value column
// of a "Name\tValue" SHOW STATUS row).
func lastField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}
