//go:build linux

package collectors

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

var redisSocketPaths = []string{
	"/run/redis/redis.sock",
	"/var/run/redis/redis.sock",
	"/run/redis/redis-server.sock",
	"/run/valkey/valkey.sock",
}

// redisPing dials network/addr and sends an inline PING, returning true if the
// server answers "+PONG" — confirming it's really Redis (or Valkey), not just
// any process bound to the port. No client binary needed.
func redisPing(network, addr string) bool {
	conn, err := net.DialTimeout(network, addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return false
	}
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	return strings.HasPrefix(string(buf[:n]), "+PONG")
}

// detectRedis returns the redis-cli connection args ("-s <sock>" or "-h..-p..")
// and a display addr for the first local Redis that answers PING, or nil.
func detectRedis() (args []string, addr string) {
	for _, sock := range redisSocketPaths {
		if redisPing("unix", sock) {
			return []string{"-s", sock}, sock
		}
	}
	if redisPing("tcp", "127.0.0.1:6379") {
		return []string{"-h", "127.0.0.1", "-p", "6379"}, "127.0.0.1:6379"
	}
	return nil, ""
}

// RedisAvailable reports whether a local Redis/Valkey server answers PING.
func RedisAvailable() bool { _, addr := detectRedis(); return addr != "" }

type RedisCollector struct{}

func NewRedisCollector() *RedisCollector { return &RedisCollector{} }

func (c *RedisCollector) Name() string           { return "Redis" }
func (c *RedisCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *RedisCollector) Collect(ctx context.Context) (interface{}, error) {
	args, addr := detectRedis()
	if addr == "" {
		return &models.RedisInfo{Detected: false}, nil
	}
	info := &models.RedisInfo{Detected: true, Addr: addr, Accepting: true}
	collectRedisMetrics(ctx, args, info)
	return info, nil
}

// collectRedisMetrics fills the metric fields via `redis-cli INFO`. Best-effort:
// if redis-cli is absent or auth-gated, MetricsRead stays false and the heuristic
// reports "couldn't look" rather than a false OK.
func collectRedisMetrics(ctx context.Context, conn []string, info *models.RedisInfo) {
	out, err := runCmd(ctx, "redis-cli", append(append([]string{}, conn...), "INFO")...)
	if err != nil || !strings.Contains(out, "redis_version:") {
		info.StatusReason = "client/replication metrics unavailable (redis-cli absent or auth required)"
		return
	}
	info.MetricsRead = true
	kv := parseRedisInfo(out)
	info.Version = kv["redis_version"]
	info.ConnectedClients = atoiSafe(kv["connected_clients"])
	info.UsedMemoryBytes = atoi64(kv["used_memory"])
	info.MaxMemoryBytes = atoi64(kv["maxmemory"])
	info.MaxMemoryPolicy = kv["maxmemory_policy"]
	info.Role = kv["role"]
	if v, ok := kv["master_link_status"]; ok {
		info.ReplLinkDown = v != "up"
		info.ReplLastIOSec = atoiSafe(kv["master_last_io_seconds_ago"])
	}
	if v, ok := kv["rdb_last_bgsave_status"]; ok {
		info.LastSaveKnown = true
		info.LastSaveOK = v == "ok"
	}
	// maxclients is a config, not in INFO.
	if c, e := runCmd(ctx, "redis-cli", append(append([]string{}, conn...), "CONFIG", "GET", "maxclients")...); e == nil {
		info.MaxClientsRead = true
		info.MaxClients = atoiSafe(lastField(strings.TrimSpace(c)))
	}
}

func parseRedisInfo(out string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			kv[k] = v
		}
	}
	return kv
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
