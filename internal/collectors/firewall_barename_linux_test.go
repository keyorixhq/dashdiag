//go:build linux

package collectors

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// recordingFWSource makes sbinToolPath("nft"/"iptables") resolve (so the gate
// passes) and records the exact command name+args handed to Run. nft/iptables
// MUST be invoked by BARE name — runCmd records the literal name as the
// capture/replay key, so an absolute path (e.g. /usr/sbin/nft) would change the
// key and make every pre-existing bundle replay as a false "could not read
// ruleset". Regression guard for that (caught only by adversarial review).
type recordingFWSource struct {
	source.Source
	runName string
	runArgs []string
	runOut  string
	runErr  error
}

func (r *recordingFWSource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	// Resolve any lookpath/<tool> probe to a path so sbinToolPath's $PATH branch
	// succeeds (it never reaches the fileExists/Stat fallback).
	return []byte("/usr/sbin/x"), nil
}

func (r *recordingFWSource) Run(_ context.Context, name string, args ...string) (source.Result, error) {
	r.runName, r.runArgs = name, args
	if r.runErr != nil {
		return source.Result{}, r.runErr
	}
	return source.Result{Stdout: []byte(r.runOut)}, nil
}

func TestFirewallInvokedByBareName(t *testing.T) {
	// Empty ruleset → security detectNFTables records the bare command name.
	t.Run("security detectNFTables", func(t *testing.T) {
		rec := &recordingFWSource{runOut: ""} // empty ruleset, exit 0
		defer SetSource(SetSource(rec))

		info := &models.SecurityInfo{}
		detectNFTables(context.Background(), info)

		if rec.runName != "nft" {
			t.Errorf("nft must be invoked by bare name (replay-key stability), got %q", rec.runName)
		}
		if !info.FirewallToolingPresent {
			t.Errorf("empty ruleset must set FirewallToolingPresent (unprotected), got %+v", info)
		}
	})

	// Health collectNFTables records the bare command name too.
	t.Run("health collectNFTables", func(t *testing.T) {
		rec := &recordingFWSource{runOut: ""}
		defer SetSource(SetSource(rec))

		_, _ = collectNFTables(context.Background(), &models.FirewallInfo{})
		if rec.runName != "nft" {
			t.Errorf("collectNFTables must invoke nft by bare name, got %q", rec.runName)
		}
	})

	// Unreadable ruleset (non-root EPERM) → FirewallUnreadable set, and the
	// on-disk-config fallback is NOT consulted (binary present but unreadable
	// must not be upgraded to a false "active"). Finding 2 guard.
	t.Run("unreadable does not fall through to config fallback", func(t *testing.T) {
		rec := &recordingFWSource{runErr: errors.New("permission denied")}
		defer SetSource(SetSource(rec))

		info := &models.SecurityInfo{}
		got := detectNFTables(context.Background(), info)
		if got {
			t.Errorf("unreadable nft must return false (not verified), got true")
		}
		if !info.FirewallUnreadable {
			t.Errorf("unreadable nft must set FirewallUnreadable, got %+v", info)
		}
		if info.FirewallActive {
			t.Errorf("unreadable nft must NOT be reported active via config fallback, got %+v", info)
		}
	})
}
