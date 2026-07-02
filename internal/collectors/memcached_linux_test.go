//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

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
