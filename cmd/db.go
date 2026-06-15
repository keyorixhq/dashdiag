package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(dbCmd)
}

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database health — local PostgreSQL, MySQL/MariaDB, and Redis/Valkey servers",
	Long: `Database health for the engines running on this host.

Detects local PostgreSQL, MySQL/MariaDB, and Redis/Valkey servers (by their unix
socket / PING) and reports liveness plus connection-saturation, memory-pressure,
and replication health. Metric depth depends on access: run as root (or a
socket-auth DB account) for the full picture.`,
	RunE: runDB,
}

func runDB(cmd *cobra.Command, _ []string) error {
	var cols []runner.Collector
	if collectors.PostgresAvailable() {
		cols = append(cols, collectors.NewPostgresCollector())
	}
	if collectors.MySQLAvailable() {
		cols = append(cols, collectors.NewMySQLCollector())
	}
	if collectors.RedisAvailable() {
		cols = append(cols, collectors.NewRedisCollector())
	}
	if collectors.MemcachedAvailable() {
		cols = append(cols, collectors.NewMemcachedCollector())
	}
	if collectors.MongoDBAvailable() {
		cols = append(cols, collectors.NewMongoDBCollector())
	}
	if len(cols) == 0 {
		fmt.Fprintln(os.Stdout, "\n🗄️  Database\n  No local database server detected (PostgreSQL, MySQL/MariaDB, Redis, Memcached, or MongoDB).")
		return nil
	}

	return runDiagnostic(cmd, diagnostic{
		label:   "Database health",
		timeout: 10 * time.Second,
		cols:    cols,
		jsonValue: func(r []runner.Result) (any, error) {
			out := map[string]any{}
			for _, res := range r {
				switch v := res.Data.(type) {
				case *models.PostgresInfo:
					out["postgres"] = v
				case *models.MySQLInfo:
					out["mysql"] = v
				case *models.RedisInfo:
					out["redis"] = v
				case *models.MemcachedInfo:
					out["memcached"] = v
				case *models.MongoDBInfo:
					out["mongodb"] = v
				}
			}
			return out, nil
		},
		render: func(r []runner.Result, mode output.OutputMode, _ time.Duration) error {
			printDB(r, mode)
			return nil
		},
	})
}

func printDB(results []runner.Result, mode output.OutputMode) {
	for _, res := range results {
		switch v := res.Data.(type) {
		case *models.PostgresInfo:
			printPostgresState(v, mode)
		case *models.MySQLInfo:
			printMySQLState(v, mode)
		case *models.RedisInfo:
			printRedisState(v, mode)
		case *models.MemcachedInfo:
			printMemcachedState(v, mode)
		case *models.MongoDBInfo:
			printMongoState(v, mode)
		}
	}

	// Verdict from the SAME heuristics dsd health uses — no drift between surfaces.
	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()
	insights := analysis.ApplyThresholds(results, analysis.DefaultThresholds(cloudEnv), cloudEnv, ctrCtx)
	printDBVerdict(insights, mode)
}

func printPostgresState(p *models.PostgresInfo, mode output.OutputMode) {
	if !p.Detected {
		return
	}
	fmt.Fprintf(os.Stdout, "\n🐘 PostgreSQL %s\n", p.ServerVersion)
	if p.Accepting {
		fmt.Fprintf(os.Stdout, "  %s accepting connections\n", asciiOr("ok", "✅", mode))
	} else {
		fmt.Fprintf(os.Stdout, "  %s NOT accepting — %s\n", asciiOr("fail", "❌", mode), p.AcceptReason)
	}
	if p.MetricsRead {
		fmt.Fprintf(os.Stdout, "  Connections: %d / %d\n", p.ActiveConns, p.MaxConnections)
		if p.IdleInTxn > 0 {
			fmt.Fprintf(os.Stdout, "  Idle in transaction: %d\n", p.IdleInTxn)
		}
		fmt.Fprintf(os.Stdout, "  Role: %s\n", roleOrPrimary(p.InRecovery, p.ReplayLagSec))
	} else {
		fmt.Fprintln(os.Stdout, "  (metrics unavailable — run as root or the postgres user)")
	}
}

func printMySQLState(m *models.MySQLInfo, mode output.OutputMode) {
	if !m.Detected {
		return
	}
	name := m.Flavor
	if name == "" {
		name = "MySQL"
	}
	fmt.Fprintf(os.Stdout, "\n🐬 %s %s\n", name, m.Version)
	if m.MetricsRead {
		fmt.Fprintf(os.Stdout, "  %s reachable\n", asciiOr("ok", "✅", mode))
		fmt.Fprintf(os.Stdout, "  Connections: %d / %d\n", m.ThreadsConnected, m.MaxConnections)
		if m.IsReplica {
			fmt.Fprintf(os.Stdout, "  Role: replica (%ds behind)\n", m.SecondsBehind)
		} else {
			fmt.Fprintln(os.Stdout, "  Role: primary")
		}
	} else {
		fmt.Fprintf(os.Stdout, "  %s reachable; metrics unavailable (run as root)\n", asciiOr("ok", "✅", mode))
	}
}

func printRedisState(r *models.RedisInfo, mode output.OutputMode) {
	if !r.Detected {
		return
	}
	fmt.Fprintf(os.Stdout, "\n🟥 Redis %s\n", r.Version)
	fmt.Fprintf(os.Stdout, "  %s answered PING\n", asciiOr("ok", "✅", mode))
	if r.MetricsRead {
		if r.MaxMemoryBytes > 0 {
			fmt.Fprintf(os.Stdout, "  Memory: %.0f%% of %s (%s)\n",
				float64(r.UsedMemoryBytes)/float64(r.MaxMemoryBytes)*100, humanBytes(r.MaxMemoryBytes), r.MaxMemoryPolicy)
		} else {
			fmt.Fprintf(os.Stdout, "  Memory: %s (no maxmemory limit)\n", humanBytes(r.UsedMemoryBytes))
		}
		fmt.Fprintf(os.Stdout, "  Role: %s · clients: %d\n", orDefault(r.Role, "master"), r.ConnectedClients)
	} else {
		fmt.Fprintln(os.Stdout, "  (metrics unavailable — install redis-cli / check auth)")
	}
}

func printMemcachedState(m *models.MemcachedInfo, mode output.OutputMode) {
	if !m.Detected {
		return
	}
	fmt.Fprintf(os.Stdout, "\n🧊 Memcached %s\n", m.Version)
	fmt.Fprintf(os.Stdout, "  %s answering\n", asciiOr("ok", "✅", mode))
	if m.MetricsRead {
		if m.LimitMaxBytes > 0 {
			fmt.Fprintf(os.Stdout, "  Memory: %.0f%% of %s\n",
				float64(m.UsedBytes)/float64(m.LimitMaxBytes)*100, humanBytes(m.LimitMaxBytes))
		}
		fmt.Fprintf(os.Stdout, "  Items: %d · connections: %d", m.CurrItems, m.CurrConnections)
		if m.MaxConnections > 0 {
			fmt.Fprintf(os.Stdout, "/%d", m.MaxConnections)
		}
		fmt.Fprintln(os.Stdout)
	} else {
		fmt.Fprintln(os.Stdout, "  (stats unavailable)")
	}
}

func printMongoState(m *models.MongoDBInfo, mode output.OutputMode) {
	if !m.Detected {
		return
	}
	fmt.Fprintf(os.Stdout, "\n🍃 MongoDB %s\n", m.Version)
	if m.MetricsRead {
		fmt.Fprintf(os.Stdout, "  %s reachable\n", asciiOr("ok", "✅", mode))
		if m.IsReplicaSet {
			primary := "no PRIMARY"
			if m.HasPrimary {
				primary = "has PRIMARY"
			}
			fmt.Fprintf(os.Stdout, "  Replica set %q: %d members, %s", m.ReplicaSetName, m.Members, primary)
			if m.DownMembers > 0 {
				fmt.Fprintf(os.Stdout, ", %d down", m.DownMembers)
			}
			fmt.Fprintln(os.Stdout)
		} else {
			fmt.Fprintln(os.Stdout, "  Standalone (not a replica set)")
		}
		fmt.Fprintf(os.Stdout, "  Connections: %d / %d\n", m.ConnCurrent, m.ConnCurrent+m.ConnAvailable)
	} else {
		fmt.Fprintf(os.Stdout, "  %s reachable; metrics unavailable (auth?)\n", asciiOr("ok", "✅", mode))
	}
}

func printDBVerdict(insights []models.Insight, mode output.OutputMode) {
	crit, warn := 0, 0
	for _, in := range insights {
		switch in.Level {
		case "CRIT":
			crit++
		case "WARN":
			warn++
		}
	}
	fmt.Fprintln(os.Stdout)
	for _, in := range insights {
		icon := asciiOr("info", "•", mode)
		switch in.Level {
		case "CRIT":
			icon = asciiOr("fail", "❌", mode)
		case "WARN":
			icon = asciiOr("warn", "⚠️", mode)
		}
		fmt.Fprintf(os.Stdout, "  %s %s\n", icon, in.Message)
	}
	switch {
	case crit > 0:
		fmt.Fprintf(os.Stdout, "%s %d database issue(s) found\n", asciiOr("fail", "❌", mode), crit+warn)
	case warn > 0:
		fmt.Fprintf(os.Stdout, "%s %d database concern(s) found\n", asciiOr("warn", "⚠️", mode), warn)
	default:
		fmt.Fprintf(os.Stdout, "%s Databases healthy. Checks passed\n", asciiOr("ok", "✅", mode))
	}
}

func roleOrPrimary(inRecovery bool, lag float64) string {
	if inRecovery {
		return fmt.Sprintf("replica (%.0fs replay lag)", lag)
	}
	return "primary"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// humanBytes renders a byte count compactly (KB/MB/GB, base 1024).
func humanBytes(b int64) string {
	const k = 1024
	switch {
	case b >= k*k*k:
		return fmt.Sprintf("%.1f GB", float64(b)/(k*k*k))
	case b >= k*k:
		return fmt.Sprintf("%.0f MB", float64(b)/(k*k))
	case b >= k:
		return fmt.Sprintf("%.0f KB", float64(b)/k)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
