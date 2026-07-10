//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestMemcachedCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewMemcachedCollector()
	if c.Name() != "Memcached" {
		t.Errorf("Name() = %q, want Memcached", c.Name())
	}
	if c.Timeout() != 4*time.Second {
		t.Errorf("Timeout() = %v, want 4s", c.Timeout())
	}
}

func memcachedJSON(out string, ok bool) []byte {
	v := struct {
		Out string `json:"out"`
		Ok  bool   `json:"ok"`
	}{Out: out, Ok: ok}
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func TestDetectMemcached(t *testing.T) {
	t.Run("found on ipv4", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"memcached/tcp/127.0.0.1:11211/version": memcachedJSON("VERSION 1.6.29\r\n", true),
		}, nil, nil)
		network, addr, version := detectMemcached(context.Background())
		if network != "tcp" || addr != "127.0.0.1:11211" || version != "1.6.29" {
			t.Errorf("got network=%q addr=%q version=%q, want tcp/127.0.0.1:11211/1.6.29", network, addr, version)
		}
	})

	t.Run("ipv4 fails, found on ipv6", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"memcached/tcp/127.0.0.1:11211/version": memcachedJSON("", false),
			"memcached/tcp/[::1]:11211/version":     memcachedJSON("VERSION 1.6.29\r\n", true),
		}, nil, nil)
		network, addr, version := detectMemcached(context.Background())
		if network != "tcp" || addr != "[::1]:11211" || version != "1.6.29" {
			t.Errorf("got network=%q addr=%q version=%q, want tcp/[::1]:11211/1.6.29", network, addr, version)
		}
	})

	t.Run("neither responds", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, nil)
		_, addr, _ := detectMemcached(context.Background())
		if addr != "" {
			t.Errorf("addr = %q, want empty", addr)
		}
		if MemcachedAvailable() {
			t.Error("MemcachedAvailable() = true, want false")
		}
	})
}

func TestMemcachedAvailable_True(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"memcached/tcp/127.0.0.1:11211/version": memcachedJSON("VERSION 1.6.29\r\n", true),
	}, nil, nil)
	if !MemcachedAvailable() {
		t.Error("MemcachedAvailable() = false, want true")
	}
}

func TestMemcachedCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewMemcachedCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MemcachedInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestMemcachedCollector_Collect_StatsUnavailable(t *testing.T) {
	// This must short-circuit before the eviction-sampling sleep -- the
	// "stats#2" cache key is deliberately left unseeded; if Collect() tried to
	// use it, cachedJSON would error and the test would still pass fast (no
	// live dial happens under the fixture source), confirming no hang either way.
	withCombinedFixture(t, map[string][]byte{
		"memcached/tcp/127.0.0.1:11211/version": memcachedJSON("VERSION 1.6.29\r\n", true),
		"memcached/tcp/127.0.0.1:11211/stats":   memcachedJSON("", false),
	}, nil, nil)
	c := NewMemcachedCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MemcachedInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if info.MetricsRead {
		t.Error("MetricsRead = true, want false")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when stats are unavailable")
	}
}

// TestMemcachedCollector_Collect_FullHappyPath pays the real 400ms sleep in
// Collect() once, covering the sleep-then-resample branch alongside the
// eviction-not-increasing and primary-stats max_connections path. Other
// branches (increasing evictions, settings fallback) are covered via the
// sub-functions directly below to avoid repeating that cost.
func TestMemcachedCollector_Collect_FullHappyPath(t *testing.T) {
	stats := "STAT curr_connections 4\r\n" +
		"STAT max_connections 1024\r\n" +
		"STAT bytes 2048\r\n" +
		"STAT limit_maxbytes 67108864\r\n" +
		"STAT evictions 10\r\n" +
		"STAT curr_items 7\r\n" +
		"END\r\n"
	stats2 := "STAT curr_connections 4\r\n" +
		"STAT max_connections 1024\r\n" +
		"STAT evictions 10\r\n" +
		"END\r\n"
	withCombinedFixture(t, map[string][]byte{
		"memcached/tcp/127.0.0.1:11211/version": memcachedJSON("VERSION 1.6.29\r\n", true),
		"memcached/tcp/127.0.0.1:11211/stats":   memcachedJSON(stats, true),
		"memcached/tcp/127.0.0.1:11211/stats#2": memcachedJSON(stats2, true),
	}, nil, nil)

	c := NewMemcachedCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MemcachedInfo)
	if !info.Detected || info.Addr != "127.0.0.1:11211" || info.Version != "1.6.29" {
		t.Errorf("info = %+v, want Detected=true Addr=127.0.0.1:11211 Version=1.6.29", info)
	}
	if !info.MetricsRead {
		t.Fatal("MetricsRead = false, want true")
	}
	if info.CurrConnections != 4 || info.CurrItems != 7 {
		t.Errorf("info = %+v, want CurrConnections=4 CurrItems=7", info)
	}
	if !info.MaxConnsRead || info.MaxConnections != 1024 {
		t.Errorf("info = %+v, want MaxConnsRead=true MaxConnections=1024 (from primary stats)", info)
	}
	if info.EvictingNow {
		t.Error("EvictingNow = true, want false (evictions did not rise)")
	}
	if info.Evictions != 10 {
		t.Errorf("Evictions = %d, want 10", info.Evictions)
	}
}

func TestMemcachedCollector_Collect_EvictingNow(t *testing.T) {
	stats := "STAT curr_connections 4\r\n" +
		"STAT max_connections 1024\r\n" +
		"STAT evictions 10\r\n" +
		"END\r\n"
	stats2 := "STAT curr_connections 4\r\n" +
		"STAT max_connections 1024\r\n" +
		"STAT evictions 55\r\n" +
		"END\r\n"
	withCombinedFixture(t, map[string][]byte{
		"memcached/tcp/127.0.0.1:11211/version": memcachedJSON("VERSION 1.6.29\r\n", true),
		"memcached/tcp/127.0.0.1:11211/stats":   memcachedJSON(stats, true),
		"memcached/tcp/127.0.0.1:11211/stats#2": memcachedJSON(stats2, true),
	}, nil, nil)

	c := NewMemcachedCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MemcachedInfo)
	if !info.EvictingNow {
		t.Error("EvictingNow = false, want true (evictions rose between samples)")
	}
	if info.Evictions != 55 {
		t.Errorf("Evictions = %d, want 55 (updated to second sample)", info.Evictions)
	}
}

func TestMemcachedCollector_Collect_MaxConnsViaSettingsFallback(t *testing.T) {
	stats := "STAT curr_connections 4\r\n" +
		"STAT evictions 10\r\n" +
		"END\r\n" // no max_connections in plain stats
	stats2 := "STAT evictions 10\r\nEND\r\n"
	settings := "STAT maxconns 2048\r\nEND\r\n"
	withCombinedFixture(t, map[string][]byte{
		"memcached/tcp/127.0.0.1:11211/version":        memcachedJSON("VERSION 1.6.29\r\n", true),
		"memcached/tcp/127.0.0.1:11211/stats":          memcachedJSON(stats, true),
		"memcached/tcp/127.0.0.1:11211/stats#2":        memcachedJSON(stats2, true),
		"memcached/tcp/127.0.0.1:11211/stats settings": memcachedJSON(settings, true),
	}, nil, nil)

	c := NewMemcachedCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MemcachedInfo)
	if !info.MaxConnsRead || info.MaxConnections != 2048 {
		t.Errorf("info = %+v, want MaxConnsRead=true MaxConnections=2048 (via settings fallback)", info)
	}
}

// memcachedVersionListener starts a TCP listener that replies to any inbound
// connection with resp (a full memcached protocol reply, e.g. "VERSION x\r\n"),
// closing after one exchange. Returns the actual local address to dial.
func memcachedVersionListener(t *testing.T, resp string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(resp))
	}()
	return ln.Addr().String()
}

// TestMemcachedCmdSampled_LiveComputeDialsMemcachedCmdLive drives
// memcachedCmdSampled's cachedJSON closure body itself (the call into
// memcachedCmdLive), which withCombinedFixture's Replay-backed source can
// never reach — an unseeded Cached key on Replay short-circuits to "not
// recorded" without calling compute at all. source.Live{}'s Cached DOES
// invoke compute, so pointing memcachedCmdSampled at a real LOCAL TCP
// listener (never a real network host) exercises the closure end-to-end.
// memcachedCmdLive itself is intentionally left uncovered elsewhere (no fake
// seam, genuinely live-network) — this test only proves the wrapping closure
// dispatches into it and records the result correctly.
func TestMemcachedCmdSampled_LiveComputeDialsMemcachedCmdLive(t *testing.T) {
	prev := SetSource(source.Live{})
	t.Cleanup(func() { SetSource(prev) })

	addr := memcachedVersionListener(t, "VERSION 1.6.29\r\n")
	out, ok := memcachedCmdSampled(context.Background(), "tcp", addr, "version", "version", false)
	if !ok {
		t.Fatal("expected ok=true from a live memcached-protocol listener")
	}
	if out != "VERSION 1.6.29\r\n" {
		t.Errorf("out = %q, want VERSION 1.6.29", out)
	}
}

func TestParseMemcachedStats(t *testing.T) {
	t.Parallel()
	t.Run("well-formed multi-line input", func(t *testing.T) {
		t.Parallel()
		kv := parseMemcachedStats("STAT curr_connections 4\r\nSTAT evictions 10\r\nEND\r\n")
		if kv["curr_connections"] != "4" || kv["evictions"] != "10" {
			t.Errorf("kv = %+v, want curr_connections=4 evictions=10", kv)
		}
	})
	t.Run("line with fewer than 3 fields is skipped", func(t *testing.T) {
		t.Parallel()
		kv := parseMemcachedStats("STAT lonely\r\nEND\r\n")
		if len(kv) != 0 {
			t.Errorf("kv = %+v, want empty", kv)
		}
	})
	t.Run("non-STAT prefixed line is skipped", func(t *testing.T) {
		t.Parallel()
		kv := parseMemcachedStats("VERSION 1.6.29\r\nSTAT evictions 10\r\nEND\r\n")
		if len(kv) != 1 || kv["evictions"] != "10" {
			t.Errorf("kv = %+v, want only evictions=10", kv)
		}
	})
}

// TestMemcachedCmdSampled_DistinctReplayKeys is a regression guard: Collect()
// issues the memcached "stats" command TWICE (before/after a short sleep) to
// detect active eviction (a rising evictions counter). Both calls used to share
// the cache key "memcached/<net>/<addr>/stats", so the Recorder's single
// blob-per-key store silently collapsed the "before" sample under the "after"
// one — on `dsd replay`, both calls returned the SAME blob, making the
// before/after delta always zero and EvictingNow unrecoverable. Using distinct
// sample discriminators ("stats" vs "stats#2") must keep both readings intact
// through record → replay while sending the identical wire command both times.
func TestMemcachedCmdSampled_DistinctReplayKeys(t *testing.T) {
	rec := source.NewRecorder(source.Live{})
	// Seed two DIFFERENT recorded responses under the two sample keys.
	if _, err := rec.Cached("memcached/tcp/127.0.0.1:11211/stats", func() ([]byte, error) {
		return []byte(`{"out":"STAT evictions 10\r\nEND\r\n","ok":true}`), nil
	}); err != nil {
		t.Fatalf("seed stats#1: %v", err)
	}
	if _, err := rec.Cached("memcached/tcp/127.0.0.1:11211/stats#2", func() ([]byte, error) {
		return []byte(`{"out":"STAT evictions 55\r\nEND\r\n","ok":true}`), nil
	}); err != nil {
		t.Fatalf("seed stats#2: %v", err)
	}

	prev := SetSource(source.NewReplay(rec.Bundle()))
	t.Cleanup(func() { SetSource(prev) })

	out1, ok1 := memcachedCmd(context.Background(), "tcp", "127.0.0.1:11211", "stats", true)
	if !ok1 {
		t.Fatal("first stats read failed")
	}
	out2, ok2 := memcachedCmdSampled(context.Background(), "tcp", "127.0.0.1:11211", "stats", "stats#2", true)
	if !ok2 {
		t.Fatal("second stats read failed")
	}

	e1 := atoi64(parseMemcachedStats(out1)["evictions"])
	e2 := atoi64(parseMemcachedStats(out2)["evictions"])
	if e1 != 10 {
		t.Errorf("first sample evictions = %d, want 10 (must not be overwritten by the second sample)", e1)
	}
	if e2 != 55 {
		t.Errorf("second sample evictions = %d, want 55", e2)
	}
	if e1 == e2 {
		t.Fatal("both samples collapsed to the same value — the before/after delta is unrecoverable on replay")
	}
}
