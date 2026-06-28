//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// These guard the opt-in/deep network probes (NFS reachability, tls --endpoint, net
// dns) against the cross-env replay-fidelity class: under `dsd replay` they must
// read the recorded result from the bundle, never re-probe the replaying machine.
// Otherwise a host with a broken endpoint/DNS would falsely read healthy when its
// capture is replayed on a machine that reaches it fine. See TRIAGE §H.

// seedReplay records one key=value via a Recorder and installs a Replay source over
// the resulting bundle, restoring the previous source on cleanup.
func seedReplay(t *testing.T, key string, value []byte) {
	t.Helper()
	rec := source.NewRecorder(source.Live{})
	if _, err := rec.Cached(key, func() ([]byte, error) { return value, nil }); err != nil {
		t.Fatalf("seed %s: %v", key, err)
	}
	prev := SetSource(source.NewReplay(rec.Bundle()))
	t.Cleanup(func() { SetSource(prev) })
}

func TestNFSReachabilityReplaysFromBundle(t *testing.T) {
	// Captured UNREACHABLE — must replay unreachable even though the test host could
	// reach a real server; the dial must not run live under replay.
	seedReplay(t, "dial/tcp/nfs.captured.example:111", []byte{'0'})
	m := &models.NFSMount{Server: "nfs.captured.example"}
	nfsCheckServer(m)
	if m.ServerReachable {
		t.Error("captured-unreachable NFS server replayed as reachable — probe hit the live machine")
	}

	// Captured REACHABLE replays reachable without dialing.
	seedReplay(t, "dial/tcp/nfs.up.example:111", []byte{'1'})
	m2 := &models.NFSMount{Server: "nfs.up.example"}
	nfsCheckServer(m2)
	if !m2.ServerReachable {
		t.Error("captured-reachable NFS server should replay reachable")
	}
}

func TestNFSReachabilityRecordingGapDegrades(t *testing.T) {
	// No recording for this server: replay must report unreachable, NOT live-dial.
	prev := SetSource(source.NewReplay(source.NewRecorder(source.Live{}).Bundle()))
	t.Cleanup(func() { SetSource(prev) })
	m := &models.NFSMount{Server: "nfs.never-recorded.example"}
	nfsCheckServer(m)
	if m.ServerReachable || m.NFSPortOpen {
		t.Error("un-recorded NFS server must degrade to unreachable under replay, not dial live")
	}
}

func TestTLSEndpointReplaysFromBundle(t *testing.T) {
	want := []models.CertInfo{{Path: "host.captured:443", Subject: "captured-leaf", ExpiresIn: 12}}
	blob, _ := json.Marshal(want)
	seedReplay(t, "tls-endpoint/host.captured:443", blob)

	got, err := CheckRemoteEndpoint(context.Background(), "host.captured:443")
	if err != nil {
		t.Fatalf("replay CheckRemoteEndpoint: %v", err)
	}
	if len(got) != 1 || got[0].Subject != "captured-leaf" || got[0].ExpiresIn != 12 {
		t.Errorf("replay returned %+v, want the recorded cert (frozen ExpiresIn=12)", got)
	}

	// Recording gap → error (couldn't verify), never a live TLS dial.
	if _, err := CheckRemoteEndpoint(context.Background(), "host.never:443"); err == nil {
		t.Error("un-recorded endpoint must error under replay, not dial live")
	}
}

func TestContainerContextReplaysFromBundle(t *testing.T) {
	// Captured on a NON-container host: stays not-in-container under replay, so a VM
	// capture replayed inside the guard's container still runs PostBoot (#586 class,
	// regressed by #592 which read container-context live at replay time).
	nonCtr, _ := json.Marshal(platform.ContainerContext{InContainer: false})
	seedReplay(t, "platform/container-context", nonCtr)
	if ContainerContextViaSource().InContainer {
		t.Error("recorded non-container must replay as not-in-container")
	}

	// Captured INSIDE a container with a cgroup CPU limit: both replay faithfully.
	ctr, _ := json.Marshal(platform.ContainerContext{InContainer: true, CPULimitCores: 2})
	seedReplay(t, "platform/container-context", ctr)
	if cc := ContainerContextViaSource(); !cc.InContainer || cc.CPULimitCores != 2 {
		t.Errorf("recorded container must replay in-container with its cgroup limit, got %+v", cc)
	}

	// Recording gap (old bundle): fall back to the zero value (not-container), matching
	// the prior hardcoded replay behavior so existing bundles/goldens are unaffected.
	prev := SetSource(source.NewReplay(source.NewRecorder(source.Live{}).Bundle()))
	t.Cleanup(func() { SetSource(prev) })
	if ContainerContextViaSource().InContainer {
		t.Error("un-recorded container-context must fall back to not-in-container")
	}
}

func TestDNSProbeReplaysFromBundle(t *testing.T) {
	// Captured on a host with BROKEN external DNS — must replay broken even though
	// the replaying machine resolves fine.
	blob, _ := json.Marshal(dnsProbeResult{ExternalResolvesOK: false, ResolvTestError: "no servers"})
	seedReplay(t, "dns/resolve-probe", blob)

	info := &models.DNSResolverInfo{}
	runDNSProbe(context.Background(), info)
	if info.ExternalResolvesOK {
		t.Error("captured broken-DNS replayed as resolving OK — probe re-resolved on the live machine")
	}
	if info.ResolvTestError != "no servers" {
		t.Errorf("ResolvTestError = %q, want the recorded reason", info.ResolvTestError)
	}
}
