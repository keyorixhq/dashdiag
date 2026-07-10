//go:build linux

package collectors

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── constructor / interface methods ──────────────────────────────────────────

func TestNewRedisCollector_NameAndTimeout(t *testing.T) {
	c := NewRedisCollector()
	if c.Name() != "Redis" {
		t.Errorf("Name() = %q, want Redis", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// ── redisPingLive (real loopback listeners, no external network) ────────────

// pongListener starts a listener on network/addr that replies to any inbound
// connection with resp (e.g. "+PONG\r\n" or a wrong-command error), closing
// after one exchange. Returns the actual local address to dial.
func pongListener(t *testing.T, network, addr, resp string) string {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("listen(%s, %s): %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(resp))
	}()
	return ln.Addr().String()
}

func TestRedisPingLive_TCP_Success(t *testing.T) {
	t.Parallel()
	addr := pongListener(t, "tcp", "127.0.0.1:0", "+PONG\r\n")
	if !redisPingLive("tcp", addr) {
		t.Error("expected true for a server answering +PONG")
	}
}

func TestRedisPingLive_TCP_WrongResponse(t *testing.T) {
	t.Parallel()
	addr := pongListener(t, "tcp", "127.0.0.1:0", "-ERR unknown command\r\n")
	if redisPingLive("tcp", addr) {
		t.Error("expected false for a non-PONG response")
	}
}

func TestRedisPingLive_TCP_ConnectionRefused(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // now guaranteed nothing is listening on this loopback port
	if redisPingLive("tcp", addr) {
		t.Error("expected false when connection is refused")
	}
}

func TestRedisPingLive_Unix_Success(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(t.TempDir(), "redis.sock")
	pongListener(t, "unix", sock, "+PONG\r\n")
	if !redisPingLive("unix", sock) {
		t.Error("expected true for a unix socket answering +PONG")
	}
}

func TestRedisPingLive_Unix_NotExist(t *testing.T) {
	t.Parallel()
	if redisPingLive("unix", filepath.Join(t.TempDir(), "absent.sock")) {
		t.Error("expected false when the socket does not exist")
	}
}

// ── redisPing (Cached wrapper) ────────────────────────────────────────────────

func TestRedisPing_Cached(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"redis-ping/unix//run/redis/redis.sock": {'1'},
	}, nil, nil)
	if !redisPing("unix", "/run/redis/redis.sock") {
		t.Error("expected true when the cached probe recorded success")
	}
}

func TestRedisPing_Cached_False(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"redis-ping/unix//run/redis/redis.sock": {'0'},
	}, nil, nil)
	if redisPing("unix", "/run/redis/redis.sock") {
		t.Error("expected false when the cached probe recorded failure")
	}
}

func TestRedisPing_NoRecording(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if redisPing("unix", "/run/redis/redis.sock") {
		t.Error("expected false when nothing was recorded for this key")
	}
}

// TestRedisPing_LiveComputeDialsRedisPingLive drives redisPing's Cached
// closure body itself (the redisPingLive dial + true/false byte encoding),
// which withCombinedFixture's Replay-backed source can never reach — an
// unseeded Cached key on Replay short-circuits to "not recorded" without
// calling compute at all (see source.Replay.Cached). source.Live{}'s Cached
// DOES invoke compute, so pointing redisPing at a real LOCAL loopback
// listener (never a real network host, same as TestRedisPingLive_TCP_Success)
// exercises the closure end-to-end on both the true and false paths.
func TestRedisPing_LiveComputeDialsRedisPingLive(t *testing.T) {
	prev := SetSource(source.Live{})
	t.Cleanup(func() { SetSource(prev) })

	t.Run("answers PONG", func(t *testing.T) {
		addr := pongListener(t, "tcp", "127.0.0.1:0", "+PONG\r\n")
		if !redisPing("tcp", addr) {
			t.Error("expected true when the live dial gets +PONG")
		}
	})

	t.Run("wrong response", func(t *testing.T) {
		addr := pongListener(t, "tcp", "127.0.0.1:0", "-ERR\r\n")
		if redisPing("tcp", addr) {
			t.Error("expected false when the live dial gets a non-PONG reply")
		}
	})
}

// ── detectRedis / RedisAvailable ──────────────────────────────────────────────

func TestDetectRedis_UnixSocketFound(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"redis-ping/unix//run/redis/redis.sock": {'1'},
	}, nil, nil)
	args, addr := detectRedis()
	if addr != "/run/redis/redis.sock" {
		t.Errorf("addr = %q, want /run/redis/redis.sock", addr)
	}
	if len(args) != 2 || args[0] != "-s" || args[1] != "/run/redis/redis.sock" {
		t.Errorf("args = %v, want [-s /run/redis/redis.sock]", args)
	}
}

func TestDetectRedis_TCPFallback(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"redis-ping/tcp/127.0.0.1:6379": {'1'},
	}, nil, nil)
	args, addr := detectRedis()
	if addr != "127.0.0.1:6379" {
		t.Errorf("addr = %q, want 127.0.0.1:6379", addr)
	}
	if len(args) != 4 || args[0] != "-h" || args[2] != "-p" {
		t.Errorf("args = %v, want [-h 127.0.0.1 -p 6379]", args)
	}
}

func TestDetectRedis_NotFound(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	args, addr := detectRedis()
	if addr != "" || args != nil {
		t.Errorf("args=%v addr=%q, want nil/empty", args, addr)
	}
}

func TestRedisAvailable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"redis-ping/tcp/127.0.0.1:6379": {'1'},
	}, nil, nil)
	if !RedisAvailable() {
		t.Error("expected true when a Redis instance answers PING")
	}
}

func TestRedisAvailable_False(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if RedisAvailable() {
		t.Error("expected false when nothing answers PING")
	}
}

// ── Collect ───────────────────────────────────────────────────────────────────

func TestRedisCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewRedisCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.RedisInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.RedisInfo", result)
	}
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestRedisCollector_Collect_Detected(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"redis-ping/tcp/127.0.0.1:6379": {'1'},
	}, nil, func(b *source.Bundle) {
		b.PutCmd("redis-cli", []string{"-h", "127.0.0.1", "-p", "6379", "INFO"},
			"# Server\r\nredis_version:7.2.4\r\n# Memory\r\nused_memory:1048576\r\nmaxmemory:0\r\n"+
				"# Clients\r\nconnected_clients:3\r\n# Replication\r\nrole:master\r\n"+
				"# Persistence\r\nrdb_last_bgsave_status:ok\r\n", 0)
		b.PutCmd("redis-cli", []string{"-h", "127.0.0.1", "-p", "6379", "CONFIG", "GET", "maxclients"},
			"maxclients\r\n10000\r\n", 0)
	})
	c := NewRedisCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.RedisInfo)
	if !info.Detected || info.Addr != "127.0.0.1:6379" || !info.Accepting {
		t.Errorf("info = %+v, want Detected/Accepting with addr 127.0.0.1:6379", info)
	}
	if !info.MetricsRead || info.Version != "7.2.4" || info.ConnectedClients != 3 {
		t.Errorf("info = %+v, want MetricsRead version=7.2.4 clients=3", info)
	}
	if info.MaxClients != 10000 || !info.MaxClientsRead {
		t.Errorf("info = %+v, want MaxClients=10000 MaxClientsRead=true", info)
	}
}

// ── collectRedisMetrics ───────────────────────────────────────────────────────

func TestCollectRedisMetrics_Full(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("redis-cli", []string{"-s", "/run/redis/redis.sock", "INFO"},
			"redis_version:7.2.4\r\n"+
				"connected_clients:5\r\n"+
				"used_memory:2097152\r\n"+
				"maxmemory:4194304\r\n"+
				"maxmemory_policy:allkeys-lru\r\n"+
				"role:slave\r\n"+
				"master_link_status:down\r\n"+
				"master_last_io_seconds_ago:42\r\n"+
				"rdb_last_bgsave_status:err\r\n", 0)
		b.PutCmd("redis-cli", []string{"-s", "/run/redis/redis.sock", "CONFIG", "GET", "maxclients"},
			"maxclients\r\n10000\r\n", 0)
	})
	info := &models.RedisInfo{}
	collectRedisMetrics(context.Background(), []string{"-s", "/run/redis/redis.sock"}, info)
	if !info.MetricsRead || info.Version != "7.2.4" || info.ConnectedClients != 5 {
		t.Errorf("info = %+v, want MetricsRead version=7.2.4 clients=5", info)
	}
	if info.UsedMemoryBytes != 2097152 || info.MaxMemoryBytes != 4194304 || info.MaxMemoryPolicy != "allkeys-lru" {
		t.Errorf("info = %+v, want used=2097152 max=4194304 policy=allkeys-lru", info)
	}
	if info.Role != "slave" || !info.ReplLinkDown || info.ReplLastIOSec != 42 {
		t.Errorf("info = %+v, want role=slave ReplLinkDown=true lastio=42", info)
	}
	if !info.LastSaveKnown || info.LastSaveOK {
		t.Errorf("info = %+v, want LastSaveKnown=true LastSaveOK=false (status=err)", info)
	}
	if info.MaxClients != 10000 || !info.MaxClientsRead {
		t.Errorf("info = %+v, want MaxClients=10000 MaxClientsRead=true", info)
	}
}

func TestCollectRedisMetrics_InfoUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("redis-cli", []string{"-h", "127.0.0.1", "-p", "6379", "INFO"})
	})
	info := &models.RedisInfo{}
	collectRedisMetrics(context.Background(), []string{"-h", "127.0.0.1", "-p", "6379"}, info)
	if info.MetricsRead {
		t.Error("expected MetricsRead=false when redis-cli is unavailable")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason explaining metrics couldn't be read")
	}
}

func TestCollectRedisMetrics_MaxClientsZeroNotTrusted(t *testing.T) {
	// A garbled/empty CONFIG GET reply parses to 0 — must NOT be trusted as a
	// real maxclients=0 value (that would silently defeat the client-saturation
	// check downstream). MaxClientsRead must stay false.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("redis-cli", []string{"-s", "/run/redis/redis.sock", "INFO"},
			"redis_version:7.2.4\r\n", 0)
		b.PutCmd("redis-cli", []string{"-s", "/run/redis/redis.sock", "CONFIG", "GET", "maxclients"},
			"garbled\r\n", 0)
	})
	info := &models.RedisInfo{}
	collectRedisMetrics(context.Background(), []string{"-s", "/run/redis/redis.sock"}, info)
	if info.MaxClientsRead || info.MaxClients != 0 {
		t.Errorf("info = %+v, want MaxClientsRead=false MaxClients=0 for an unparseable reply", info)
	}
}

func TestCollectRedisMetrics_NoReplicationOrPersistenceFields(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("redis-cli", []string{"-s", "/run/redis/redis.sock", "INFO"},
			"redis_version:7.2.4\r\nrole:master\r\n", 0)
		b.PutCmdNotFound("redis-cli", []string{"-s", "/run/redis/redis.sock", "CONFIG", "GET", "maxclients"})
	})
	info := &models.RedisInfo{}
	collectRedisMetrics(context.Background(), []string{"-s", "/run/redis/redis.sock"}, info)
	if !info.MetricsRead || info.Role != "master" {
		t.Errorf("info = %+v, want MetricsRead role=master", info)
	}
	if info.LastSaveKnown {
		t.Error("expected LastSaveKnown=false when rdb_last_bgsave_status absent")
	}
	if info.MaxClientsRead {
		t.Error("expected MaxClientsRead=false when CONFIG GET fails")
	}
}
