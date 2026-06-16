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

// parseMySQLReplica reads SHOW SLAVE STATUS (works on MariaDB and MySQL 8) and
// records replica lag. Empty output ⇒ not a replica.
func parseMySQLReplica(q func(string) (string, bool), info *models.MySQLInfo) {
	out, ok := q("SHOW SLAVE STATUS\\G")
	if !ok || strings.TrimSpace(out) == "" {
		return
	}
	info.IsReplica = true
	for _, line := range strings.Split(out, "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		if strings.TrimSpace(k) == "Seconds_Behind_Master" {
			if sb := strings.TrimSpace(v); sb != "" && sb != "NULL" {
				info.SecondsBehind = atoiSafe(sb)
			}
		}
	}
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
