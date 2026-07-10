//go:build linux

package collectors

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// errRoundTripper makes every HTTP request fail immediately — simulating a
// /networks API error (Docker socket unreachable, Podman/custom-network-only
// host) so getContainerNetworkMTU deterministically returns 0.
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated: no docker daemon reachable")
}

// TestCollectNetworkHealth_MTUUnavailableStillChecksIPForward is a regression
// guard: collectIPForwarding/collectFirewalldCheck used to sit AFTER two
// MTU-related early returns, even though they're completely independent of
// MTU. A /networks API error, a Podman/custom-network-only host, or a host
// with no discoverable non-loopback interface meant IPForwardChecked never got
// set — so an ip_forward=0 host (all container networking broken) could never
// CRIT.
func TestCollectNetworkHealth_MTUUnavailableStillChecksIPForward(t *testing.T) {
	client := &http.Client{Transport: errRoundTripper{}}
	var info models.DockerInfo
	collectNetworkHealth(context.Background(), client, &info)

	if info.ContainerMTU != 0 {
		t.Fatalf("expected ContainerMTU=0 (API unreachable), got %d", info.ContainerMTU)
	}
	if !info.IPForwardChecked {
		t.Error("IPForwardChecked should be true — ip_forward is readable regardless of MTU/API state")
	}
}

// TestCollectNetworkHealth_MTUMismatch drives the full happy path: both
// containerMTU and hostMTU are readable and the container's MTU exceeds the
// host's, so MTUMismatch must be set — the fragmentation-risk finding.
func TestCollectNetworkHealth_MTUMismatch(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/networks": []byte(`[{"Name":"bridge","Options":{"com.docker.network.driver.mtu":"9000"}}]`),
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"lo", "docker0", "eth0"})
		b.PutFile("/sys/class/net/eth0/mtu", []byte("1500\n"))
	})
	var info models.DockerInfo
	collectNetworkHealth(context.Background(), client, &info)

	if info.ContainerMTU != 9000 || info.HostMTU != 1500 {
		t.Fatalf("ContainerMTU=%d HostMTU=%d, want 9000/1500", info.ContainerMTU, info.HostMTU)
	}
	if !info.MTUMismatch {
		t.Error("expected MTUMismatch=true — container MTU (9000) exceeds host MTU (1500)")
	}
}

// TestCollectNetworkHealth_MTUMatchNoMismatch confirms equal container/host
// MTUs do NOT set MTUMismatch (the normal, healthy case).
func TestCollectNetworkHealth_MTUMatchNoMismatch(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/networks": []byte(`[{"Name":"bridge","Options":{}}]`),
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"lo", "eth0"})
		b.PutFile("/sys/class/net/eth0/mtu", []byte("1500\n"))
	})
	var info models.DockerInfo
	collectNetworkHealth(context.Background(), client, &info)

	if info.ContainerMTU != 1500 || info.HostMTU != 1500 {
		t.Fatalf("ContainerMTU=%d HostMTU=%d, want 1500/1500", info.ContainerMTU, info.HostMTU)
	}
	if info.MTUMismatch {
		t.Error("expected MTUMismatch=false when container and host MTU match")
	}
}

// TestCollectNetworkHealth_ContainerMTUFoundButHostUnavailable exercises the
// second early-return: containerMTU is readable but hostMTU is not.
func TestCollectNetworkHealth_ContainerMTUFoundButHostUnavailable(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/networks": []byte(`[{"Name":"bridge","Options":{}}]`),
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"lo"})
	})
	var info models.DockerInfo
	collectNetworkHealth(context.Background(), client, &info)

	if info.ContainerMTU != 1500 {
		t.Fatalf("ContainerMTU = %d, want 1500", info.ContainerMTU)
	}
	if info.HostMTU != 0 || info.MTUMismatch {
		t.Errorf("HostMTU=%d MTUMismatch=%v, want 0/false when no host interface is discoverable", info.HostMTU, info.MTUMismatch)
	}
}
