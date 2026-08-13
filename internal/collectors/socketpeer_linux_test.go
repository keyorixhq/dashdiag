//go:build linux

package collectors

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestProbeSocketPeerCred_LiveMatchesOwnProcess drives the real Live dial +
// SO_PEERCRED syscall (no fixture) against a unix socket this test process
// itself listens on, so the kernel-reported peer UID must equal our own
// os.Getuid() — the one property SO_PEERCRED guarantees can't be spoofed by
// whatever the peer claims over the wire.
func TestProbeSocketPeerCred_LiveMatchesOwnProcess(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	cred := probeSocketPeerCred(sockPath)
	if !cred.Present {
		t.Fatal("Present = false, want true — a real listener is up")
	}
	if cred.UID != uint32(os.Getuid()) {
		t.Errorf("UID = %d, want %d (this process's own uid)", cred.UID, os.Getuid())
	}
}

// TestProbeSocketPeerCred_RecordReplayRoundTrip is the hermeticity regression
// test: a replayed bundle must NEVER dial the replaying machine's own
// filesystem/socket namespace. It records the live probe against a real
// listener, then closes that listener and swaps in a Replay source — if
// probeSocketPeerCred tried to dial live on replay it would now get
// Present:false (nothing is listening any more); getting back the ORIGINAL
// recorded, present, correct-uid result proves the replay path never
// touched the network/filesystem at all.
func TestProbeSocketPeerCred_RecordReplayRoundTrip(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	t.Cleanup(func() { SetSource(prev) })

	live := probeSocketPeerCred(sockPath)
	if !live.Present || live.UID != uint32(os.Getuid()) {
		t.Fatalf("live probe = %+v, want Present=true UID=%d", live, os.Getuid())
	}

	// Kill the real listener AND remove the socket file — if replay fell back
	// to a live dial it would now fail (Present:false), unmasking the bug.
	_ = ln.Close()
	_ = os.Remove(sockPath)

	replay := source.NewReplay(rec.Bundle())
	SetSource(replay)

	got := probeSocketPeerCred(sockPath)
	if got != live {
		t.Errorf("replay probe = %+v, want the recorded %+v — replay must never dial live (recording gap or a live fallback would both show up as a mismatch)", got, live)
	}
}

// TestProbeSocketPeerCred_RecordingGap covers an older bundle captured before
// this check existed — Cached returns ErrNotRecorded, and the result must
// resolve to Present:false (never silently treated as trusted).
func TestProbeSocketPeerCred_RecordingGap(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil) // no "socketpeercred/" entry
	got := probeSocketPeerCred("/var/run/mysqld/mysqld.sock")
	if got.Present {
		t.Errorf("Present = true, want false on a recording gap, got %+v", got)
	}
}

func TestSocketPeerTrusted(t *testing.T) {
	const sock = "/tmp/fake.sock"

	t.Run("root peer is always trusted", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"socketpeercred/" + sock: []byte(`{"uid":0,"present":true}`),
		}, nil, nil)
		trusted, verified := socketPeerTrusted(sock, "mysql")
		if !verified || !trusted {
			t.Errorf("trusted=%v verified=%v, want true,true for uid 0", trusted, verified)
		}
	})

	t.Run("service-account peer is trusted", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"socketpeercred/" + sock: []byte(`{"uid":27,"present":true}`),
			"userlookup/mysql":       []byte("27"),
		}, nil, nil)
		trusted, verified := socketPeerTrusted(sock, "mysql")
		if !verified || !trusted {
			t.Errorf("trusted=%v verified=%v, want true,true when peer uid matches the service account", trusted, verified)
		}
	})

	t.Run("mismatched uid is verified but untrusted", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"socketpeercred/" + sock: []byte(`{"uid":1000,"present":true}`),
			"userlookup/mysql":       []byte("27"),
		}, nil, nil)
		trusted, verified := socketPeerTrusted(sock, "mysql")
		if !verified {
			t.Error("verified = false, want true — the probe itself succeeded")
		}
		if trusted {
			t.Error("trusted = true, want false — peer uid does not match root or the service account")
		}
	})

	t.Run("unresolvable service account is verified but untrusted", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"socketpeercred/" + sock: []byte(`{"uid":1000,"present":true}`),
			"userlookup/mysql":       []byte("-1"), // account doesn't exist on this host
		}, nil, nil)
		trusted, verified := socketPeerTrusted(sock, "mysql")
		if !verified || trusted {
			t.Errorf("trusted=%v verified=%v, want false,true when the expected account can't be resolved", trusted, verified)
		}
	})

	t.Run("probe failure is unverified, never trusted", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, nil) // no cached entry — recording gap / probe failure
		trusted, verified := socketPeerTrusted(sock, "mysql")
		if verified || trusted {
			t.Errorf("trusted=%v verified=%v, want false,false when the probe itself failed", trusted, verified)
		}
	})
}

func TestLookupUserUID(t *testing.T) {
	t.Run("resolves a cached uid", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"userlookup/postgres": []byte("26"),
		}, nil, nil)
		uid, ok := lookupUserUID("postgres")
		if !ok || uid != 26 {
			t.Errorf("lookupUserUID() = %d, %v, want 26, true", uid, ok)
		}
	})

	t.Run("negative sentinel means account not found", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"userlookup/nosuchuser": []byte("-1"),
		}, nil, nil)
		_, ok := lookupUserUID("nosuchuser")
		if ok {
			t.Error("ok = true, want false for the -1 not-found sentinel")
		}
	})

	t.Run("recording gap is not found", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, nil)
		_, ok := lookupUserUID("mysql")
		if ok {
			t.Error("ok = true, want false on a recording gap")
		}
	})

	// Regression test for a CodeQL "incorrect integer conversion" finding
	// (PR #995): a naive strconv.Atoi + uint32(n) cast would silently WRAP a
	// value larger than math.MaxUint32 into a small/zero uint32 instead of
	// erroring — e.g. a crafted/corrupt cached value or replay bundle entry.
	// strconv.ParseUint(raw, 10, 32) rejects it outright.
	t.Run("out-of-range value is rejected, not silently wrapped", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"userlookup/toolarge": []byte("4294967296"), // math.MaxUint32 + 1
		}, nil, nil)
		uid, ok := lookupUserUID("toolarge")
		if ok {
			t.Errorf("ok = true, want false for a value exceeding math.MaxUint32 (got uid=%d — a silent wrap would show up here)", uid)
		}
	})
}
