package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	dbCatPostgres         = "Postgres"
	dbCatRedis            = "Redis"
	dbCatMySQL            = "MySQL"
	dbInspectRedisPrefix  = "to inspect: redis-cli -s "
	dbInspectMemcachedPfx = "to inspect: echo stats | nc "
)

// checkPostgres surfaces health issues for a local PostgreSQL server. Gated on
// Detected (a reachable local socket), silent on hosts without one. Returns nil
// when healthy — except when the server is up but its metrics couldn't be read,
// which is reported as INFO so an inaccessible server is never a silent OK.
func checkPostgres(pg models.PostgresInfo) []models.Insight {
	if !pg.Detected {
		return nil
	}
	var out []models.Insight

	// A running server that refuses connections is a live outage.
	if !pg.Accepting {
		reason := pg.AcceptReason
		if reason == "" {
			reason = "not accepting connections"
		}
		// pg.SocketDir is spliced unescaped into a copy-pasteable "to inspect:"
		// hint below; validate before use (see looksLikeSafeToken).
		socketDir := pg.SocketDir
		if !looksLikeSafeToken(socketDir) {
			socketDir = "<socket-dir>"
		}
		return []models.Insight{insight("CRIT", dbCatPostgres,
			fmt.Sprintf("PostgreSQL is up but not accepting connections — %s", reason),
			[]string{
				"to inspect: pg_isready -h " + socketDir,
				"to inspect: tail -n 50 the server log (often /var/log/postgresql/*.log)",
				"note: common causes — recovery in progress, max_connections reached, or a full data disk",
			},
		)}
	}

	if !pg.MetricsRead {
		return []models.Insight{unverifiedInsight("INFO", dbCatPostgres,
			"PostgreSQL is up and accepting connections; connection/replication metrics were not read",
			[]string{
				"note: run dsd as root or the postgres user for connection-saturation and replica-lag checks",
				"to inspect: sudo -u postgres psql -c 'SELECT count(*), current_setting(''max_connections'') FROM pg_stat_activity'",
			},
		)}
	}

	// Connection saturation — the classic "FATAL: too many connections" outage.
	if pg.MaxConnections > 0 {
		ratio := float64(pg.ActiveConns) / float64(pg.MaxConnections)
		switch {
		case ratio >= 0.95:
			out = append(out, insight("CRIT", dbCatPostgres,
				fmt.Sprintf("PostgreSQL connections at %d/%d (%.0f%%) — new connections will be refused",
					pg.ActiveConns, pg.MaxConnections, ratio*100),
				[]string{
					"to inspect: SELECT state, count(*) FROM pg_stat_activity GROUP BY state",
					"to fix: add a connection pooler (pgbouncer), or raise max_connections (costs RAM)",
				}))
		case ratio >= 0.80:
			out = append(out, insight("WARN", dbCatPostgres,
				fmt.Sprintf("PostgreSQL connections at %d/%d (%.0f%%) — approaching the limit",
					pg.ActiveConns, pg.MaxConnections, ratio*100),
				[]string{"to inspect: SELECT state, count(*) FROM pg_stat_activity GROUP BY state",
					"note: a connection pooler (pgbouncer) is the usual fix before raising max_connections"}))
		}
	} else {
		// A real server never reports max_connections==0. MetricsRead is true
		// here, so this is a malformed/short read (or a rogue process answering
		// on the socket) — say the saturation check wasn't assessed rather than
		// silently skipping it, matching the MySQL/Redis/Memcached sibling paths
		// in this file.
		out = append(out, unverifiedInsight("INFO", dbCatPostgres,
			"PostgreSQL connection-saturation could not be assessed — max_connections read as 0",
			[]string{
				"to inspect: sudo -u postgres psql -c \"SELECT current_setting('max_connections')\"",
			},
		))
	}

	// Idle-in-transaction connections hold locks and block VACUUM → bloat.
	if pg.IdleInTxn >= 5 {
		out = append(out, insight("WARN", dbCatPostgres,
			fmt.Sprintf("%d connection(s) idle in transaction — they hold locks and block VACUUM (bloat risk)", pg.IdleInTxn),
			[]string{
				"to inspect: SELECT pid, state, query FROM pg_stat_activity WHERE state='idle in transaction'",
				"to fix: set idle_in_transaction_session_timeout, or fix the app to commit/rollback promptly",
			}))
	}

	// Replica falling behind. ReplayLagSec alone climbs unboundedly whenever the
	// PRIMARY is simply idle (no new transactions to replay) — gate on
	// ReplayCaughtUp (last-received vs last-replayed WAL position) so a
	// perfectly-synced replica during an idle period doesn't false-fire.
	if pg.InRecovery && !pg.ReplayCaughtUp && pg.ReplayLagSec > 300 {
		out = append(out, insight("WARN", dbCatPostgres,
			fmt.Sprintf("replica is %.0fs behind the primary — replay lag growing", pg.ReplayLagSec),
			[]string{
				"to inspect: SELECT now()-pg_last_xact_replay_timestamp() AS lag",
				"note: check WAL receiver, network to primary, and replica I/O headroom",
			}))
	}

	return out
}

// checkMySQL surfaces health issues for a local MySQL / MariaDB server. Same
// shape and discipline as checkPostgres: gated on Detected, silent when healthy,
// and never a silent OK when the metrics couldn't be read.
func checkMySQL(my models.MySQLInfo) []models.Insight {
	if !my.Detected {
		return nil
	}
	name := my.Flavor
	if name == "" {
		name = dbCatMySQL
	}
	// my.SocketPath is spliced unescaped into copy-pasteable "to inspect:"
	// mysqladmin hints below; validate once and reuse (see looksLikeSafeToken).
	socketPath := my.SocketPath
	if !looksLikeSafeToken(socketPath) {
		socketPath = "<socket-path>"
	}
	if !my.MetricsRead {
		return []models.Insight{unverifiedInsight("INFO", dbCatMySQL,
			fmt.Sprintf("%s is reachable; connection/replication metrics were not read", name),
			[]string{
				"note: run dsd as root (root@localhost socket auth) for connection-saturation and replica-lag checks",
				"to inspect: mysqladmin --socket=" + socketPath + " status",
			},
		)}
	}

	var out []models.Insight

	// Connection saturation — the "ERROR 1040: Too many connections" outage. Needs
	// BOTH counters (ConnStatsRead); a partial read would compute a bogus 0 ratio.
	if my.ConnStatsRead && my.MaxConnections > 0 {
		ratio := float64(my.ThreadsConnected) / float64(my.MaxConnections)
		switch {
		case ratio >= 0.95:
			out = append(out, insight("CRIT", dbCatMySQL,
				fmt.Sprintf("%s connections at %d/%d (%.0f%%) — new connections will be refused (ERROR 1040)",
					name, my.ThreadsConnected, my.MaxConnections, ratio*100),
				[]string{
					"to inspect: SHOW PROCESSLIST",
					"to fix: add a connection pooler (ProxySQL), or raise max_connections (costs RAM)",
				}))
		case ratio >= 0.80:
			out = append(out, insight("WARN", dbCatMySQL,
				fmt.Sprintf("%s connections at %d/%d (%.0f%%) — approaching the limit",
					name, my.ThreadsConnected, my.MaxConnections, ratio*100),
				[]string{"to inspect: SHOW PROCESSLIST",
					"note: a connection pooler is the usual fix before raising max_connections"}))
		}
	} else if !my.ConnStatsRead {
		// max_connections / Threads_connected come from separate queries that can
		// fail after VERSION() succeeded; without both the saturation check can't
		// run. Surface that rather than let an unread dimension pass as clean.
		out = append(out, unverifiedInsight("INFO", dbCatMySQL,
			fmt.Sprintf("%s metrics were read, but the connection counters were not — connection-saturation was not assessed", name),
			[]string{"to inspect: mysqladmin --socket=" + socketPath + " status"}))
	} else {
		// internal-analysis-03-02: ConnStatsRead is true but MaxConnections <= 0
		// — a spoofed/corrupted response (max_connections should never be 0 on a
		// running server). Neither branch above applies; without this, the gap
		// silently emitted nothing instead of disclosing the implausible read.
		out = append(out, unverifiedInsight("INFO", dbCatMySQL,
			fmt.Sprintf("%s reported max_connections=%d, which is implausible — connection-saturation was not assessed", name, my.MaxConnections),
			[]string{"to inspect: mysqladmin --socket=" + socketPath + " variables | grep max_connections"}))
	}

	// Replication stopped — the worst replica state. Seconds_Behind_Master reads
	// NULL here, so the lag check below would report 0s and the replica would look
	// healthy while serving ever-staler data. CRIT, ahead of the lag WARN.
	if my.IsReplica && my.ReplStopped {
		out = append(out, insight("CRIT", dbCatMySQL,
			"replication is STOPPED on this replica — it is serving stale data and not following the primary",
			[]string{
				"to inspect: SHOW SLAVE STATUS\\G  (Slave_IO_Running / Slave_SQL_Running should both be 'Yes')",
				"to inspect: check Last_IO_Error / Last_SQL_Error for the cause",
				"to fix: resolve the error, then START SLAVE  (MySQL 8.4+: START REPLICA)",
			}))
	}

	// Replica falling behind.
	if my.IsReplica && !my.ReplStopped && my.SecondsBehind > 300 {
		out = append(out, insight("WARN", dbCatMySQL,
			fmt.Sprintf("replica is %ds behind the primary — replication lag growing", my.SecondsBehind),
			[]string{
				"to inspect: SHOW SLAVE STATUS\\G  (look at Seconds_Behind_Master, Slave_IO/SQL_Running)",
				"note: check the replication threads, network to the primary, and replica I/O headroom",
			}))
	}

	return out
}

// checkRedis surfaces health issues for a local Redis/Valkey server. Same shape
// and discipline as the SQL collectors: gated on Detected, silent when healthy,
// never a silent OK when the metrics couldn't be read.
func checkRedis(r models.RedisInfo) []models.Insight {
	if !r.Detected {
		return nil
	}
	// r.Addr is spliced unescaped into copy-pasteable "to inspect:" redis-cli
	// hints throughout this function; validate once and reuse (see
	// looksLikeSafeToken).
	addr := r.Addr
	if !looksLikeSafeToken(addr) {
		addr = "<redis-addr>"
	}
	if !r.MetricsRead {
		return []models.Insight{unverifiedInsight("INFO", dbCatRedis,
			"Redis is reachable (answered PING); memory/replication metrics were not read",
			[]string{
				"note: install redis-cli (or pass auth) for memory-pressure and replica checks",
				dbInspectRedisPrefix + addr + " INFO",
			},
		)}
	}

	var out []models.Insight

	// Memory pressure against maxmemory — the eviction / OOM-write-rejection cliff.
	if r.MaxMemoryBytes > 0 {
		ratio := float64(r.UsedMemoryBytes) / float64(r.MaxMemoryBytes)
		noEvict := r.MaxMemoryPolicy == "noeviction"
		switch {
		case ratio >= 0.95 && noEvict:
			out = append(out, insight("CRIT", dbCatRedis,
				fmt.Sprintf("memory at %.0f%% of maxmemory with noeviction policy — writes will be rejected (OOM)", ratio*100),
				[]string{
					dbInspectRedisPrefix + addr + " INFO memory",
					"to fix: raise maxmemory, set an eviction policy, or shed keys",
				}))
		case ratio >= 0.95:
			out = append(out, insight("WARN", dbCatRedis,
				fmt.Sprintf("memory at %.0f%% of maxmemory — actively evicting keys (%s)", ratio*100, r.MaxMemoryPolicy),
				[]string{dbInspectRedisPrefix + addr + " INFO stats | grep evicted_keys"}))
		case ratio >= 0.85:
			out = append(out, insight("WARN", dbCatRedis,
				fmt.Sprintf("memory at %.0f%% of maxmemory — approaching the limit", ratio*100),
				[]string{dbInspectRedisPrefix + addr + " INFO memory"}))
		}
	}

	// Client saturation (default maxclients is 10000, so this is a real signal).
	if r.MaxClients > 0 && float64(r.ConnectedClients)/float64(r.MaxClients) >= 0.90 {
		out = append(out, insight("WARN", dbCatRedis,
			fmt.Sprintf("clients at %d/%d — approaching maxclients (new connections will be refused at the limit)",
				r.ConnectedClients, r.MaxClients),
			[]string{dbInspectRedisPrefix + addr + " INFO clients"}))
	} else if !r.MaxClientsRead {
		// maxclients comes from a separate CONFIG GET that can fail after INFO
		// succeeded; without it the saturation check above can't run. Don't let an
		// unread limit pass as clean.
		out = append(out, unverifiedInsight("INFO", dbCatRedis,
			"Redis metrics were read, but maxclients could not be — client-saturation was not assessed",
			[]string{dbInspectRedisPrefix + addr + " CONFIG GET maxclients"}))
	}

	// A replica that lost its link is serving stale data.
	if r.Role == "slave" && r.ReplLinkDown {
		out = append(out, insight("CRIT", dbCatRedis,
			"replica is disconnected from its master — it is serving stale data and not receiving updates",
			[]string{
				dbInspectRedisPrefix + addr + " INFO replication",
				"note: check the master, network, and replica auth (masterauth)",
			}))
	}

	// Persistence broken — recent writes are not durable.
	if r.LastSaveKnown && !r.LastSaveOK {
		out = append(out, insight("WARN", dbCatRedis,
			"last RDB background save failed — recent writes are not being persisted to disk",
			[]string{
				dbInspectRedisPrefix + addr + " INFO persistence",
				"note: common causes — no disk space, or the data dir is not writable",
			}))
	}

	return out
}

// checkMemcached surfaces health for a local memcached server. memcached degrades
// by evicting rather than blocking, so its signals are WARN-level cache pressure.
func checkMemcached(m models.MemcachedInfo) []models.Insight {
	if !m.Detected {
		return nil
	}
	// m.Addr is spliced unescaped into copy-pasteable "to inspect:" hints
	// throughout this function; validate once and reuse (see
	// looksLikeSafeToken).
	addr := m.Addr
	if !looksLikeSafeToken(addr) {
		addr = "<memcached-addr>"
	}
	if !m.MetricsRead {
		return []models.Insight{unverifiedInsight("INFO", "Memcached",
			"memcached is reachable; its stats could not be read",
			[]string{dbInspectMemcachedPfx + addr},
		)}
	}

	var out []models.Insight

	// Active eviction — the working set exceeds the cache, so memcached is dropping
	// live keys to make room (hit rate degrades, recently-set keys vanish early).
	// Keyed on a rising eviction count (now), not a bytes ratio: memcached evicts to
	// stay under limit_maxbytes, so the ratio rarely reflects the pressure.
	if m.EvictingNow {
		out = append(out, insight("WARN", "Memcached",
			"actively evicting keys — the working set exceeds the cache (memory pressure)",
			[]string{
				dbInspectMemcachedPfx + addr + "  (watch evictions climb)",
				"to fix: raise -m (max memory) or reduce what's cached",
			}))
	}

	// Connection saturation — at maxconns, new connections are refused.
	if m.MaxConnections > 0 && float64(m.CurrConnections)/float64(m.MaxConnections) >= 0.90 {
		out = append(out, insight("WARN", "Memcached",
			fmt.Sprintf("connections at %d/%d — approaching maxconns (new connections refused at the limit)",
				m.CurrConnections, m.MaxConnections),
			[]string{dbInspectMemcachedPfx + addr + "  (curr_connections)", "to fix: raise -c (max connections)"}))
	} else if !m.MaxConnsRead {
		// stats were read but neither plain stats nor `stats settings` exposed a
		// maxconns value — the connection-saturation check above couldn't run. Say
		// so honestly rather than passing clean (mirrors checkRedis / checkMySQL).
		out = append(out, insight("INFO", "Memcached",
			"Memcached metrics were read, but max_connections could not be — connection-saturation was not assessed",
			[]string{"to inspect: echo stats settings | nc " + addr + "  (look for maxconns)"}))
	}

	return out
}
