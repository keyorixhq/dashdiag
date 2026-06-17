package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestNFSHasV3Mount + TestNFSRetransConcern pin the exported predicates that the
// `dsd net deep` renderer and checkNFS (dsd health) now share, so the two can't
// drift back apart (the renderer used to false-alarm on v4-only rpcbind and on
// the cumulative retrans counter).
func TestNFSHasV3Mount(t *testing.T) {
	v4only := []models.NFSMount{{Mount: "/a", FSType: "nfs4"}}
	if NFSHasV3Mount(v4only) {
		t.Errorf("v4-only mounts must not count as v3 (rpcbind not required)")
	}
	mixed := []models.NFSMount{{FSType: "nfs4"}, {FSType: "nfs"}}
	if !NFSHasV3Mount(mixed) {
		t.Errorf("an ambiguous 'nfs' mount must count as possibly-v3")
	}
	if NFSHasV3Mount(nil) {
		t.Errorf("no mounts must not require rpcbind")
	}
}

func TestNFSRetransConcern(t *testing.T) {
	// High raw count but tiny rate over a long uptime → NOT a concern (the bug).
	lowRate := models.NFSInfo{RPCCalls: 5_000_000, RetransPerMin: 800}
	if NFSRetransConcern(lowRate) {
		t.Errorf("0.016%% retrans rate must not flag (raw count is cumulative)")
	}
	// Genuinely high rate over enough calls → concern.
	highRate := models.NFSInfo{RPCCalls: 10000, RetransPerMin: 800}
	if !NFSRetransConcern(highRate) {
		t.Errorf("8%% retrans rate over 10k calls must flag")
	}
	// Below the call-volume floor → don't flag a freshly-mounted share.
	lowVolume := models.NFSInfo{RPCCalls: 100, RetransPerMin: 50}
	if NFSRetransConcern(lowVolume) {
		t.Errorf("below the 1000-call floor must not flag")
	}
	// A stale mount present → retrans is not the story; don't add noise.
	withStale := models.NFSInfo{RPCCalls: 10000, RetransPerMin: 800, StaleMounts: 1}
	if NFSRetransConcern(withStale) {
		t.Errorf("with a stale mount present, retrans must not flag")
	}
}
