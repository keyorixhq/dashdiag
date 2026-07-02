//go:build linux

package collectors

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
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
