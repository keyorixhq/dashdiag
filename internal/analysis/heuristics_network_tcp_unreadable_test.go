package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckNetwork_SockstatUnreadable: a /proc/net/sockstat read failure
// leaves TimeWaitCount at its zero value, and TimeWaitLevel(0) returns ""
// (no insight) — indistinguishable from a genuinely quiet host without this
// disclosure. Must surface as an unverified INFO, never fold to silence.
func TestCheckNetwork_SockstatUnreadable(t *testing.T) {
	t.Parallel()

	insights := checkNetwork(models.NetworkInfo{SockstatUnreadable: true})
	assertLevel(t, insights, "INFO")
	found := false
	for _, ins := range insights {
		if ins.Unverified {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an Unverified insight, got %+v", insights)
	}
}

// TestCheckNetwork_NetstatUnreadable: same false-OK shape for
// /proc/net/netstat — DeepTCPCounterLevel floors out at 0 for all three
// TcpExt counters, so a read failure produces zero insights either way.
func TestCheckNetwork_NetstatUnreadable(t *testing.T) {
	t.Parallel()

	insights := checkNetwork(models.NetworkInfo{NetstatUnreadable: true})
	assertLevel(t, insights, "INFO")
	found := false
	for _, ins := range insights {
		if ins.Unverified {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an Unverified insight, got %+v", insights)
	}
}

// TestCheckNetwork_TCPCountersCleanRead confirms the genuinely-clean case
// (both files read fine, all counters legitimately 0) stays silent for these
// two signals specifically — the fix must not introduce noise on a healthy,
// low-traffic host.
func TestCheckNetwork_TCPCountersCleanRead(t *testing.T) {
	t.Parallel()

	insights := checkNetwork(models.NetworkInfo{})
	for _, ins := range insights {
		if ins.Unverified {
			t.Fatalf("expected no unverified TCP-counter disclosure on a clean read, got %+v", insights)
		}
	}
}

// TestCheckNetwork_NetstatUnreadableDoesNotSuppressTimeWait: the two deep-TCP
// disclosures are independent — a netstat failure must not swallow a real
// TIME_WAIT finding derived from a successfully-read sockstat.
func TestCheckNetwork_NetstatUnreadableDoesNotSuppressTimeWait(t *testing.T) {
	t.Parallel()

	insights := checkNetwork(models.NetworkInfo{
		NetstatUnreadable: true,
		TimeWaitCount:     6000, // well past TimeWaitCritCount
	})
	assertLevel(t, insights, "CRIT")
	hasDisclosure := false
	for _, ins := range insights {
		if ins.Unverified {
			hasDisclosure = true
		}
	}
	if !hasDisclosure {
		t.Fatalf("expected both the NetstatUnreadable disclosure and the real TIME_WAIT CRIT, got %+v", insights)
	}
}
