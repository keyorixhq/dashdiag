//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func seedDMI(vendor string) func(b *source.Bundle) {
	return func(b *source.Bundle) { b.PutFile("/sys/class/dmi/id/sys_vendor", []byte(vendor+"\n")) }
}

// DD-COLLECTOR-GAPS-1 Medium #7: the registration gate is itself an IMDS probe.
// A transient miss on a host DMI says is a cloud VM must still register the
// collector (which then reports "metadata could not be read", Unverified) rather
// than read as "not cloud" and silently drop the spot-termination check.
func TestIsCloudInstance_TransientMissOnCloudDMIStillRegisters(t *testing.T) {
	t.Setenv("DSD_ALLOW_NETWORK", "1")
	withCombinedFixture(t, nil, nil, seedDMI("Amazon EC2"))
	if !IsCloudInstance() {
		t.Fatal("IsCloudInstance() = false for an EC2 DMI host whose IMDS probe failed; the collector would never run")
	}
}

func TestIsCloudInstance_BareMetalWithNoIMDSIsNotCloud(t *testing.T) {
	t.Setenv("DSD_ALLOW_NETWORK", "1")
	withCombinedFixture(t, nil, nil, seedDMI("Dell Inc."))
	if IsCloudInstance() {
		t.Fatal("IsCloudInstance() = true for a bare-metal host with no IMDS")
	}
}

// Offline (the default) is policy, not a failure: no probe ran, so no
// "could not be read" disclosure on every default run.
func TestIsCloudInstance_OfflineCloudDMIDoesNotRegister(t *testing.T) {
	t.Setenv("DSD_ALLOW_NETWORK", "")
	withCombinedFixture(t, nil, nil, seedDMI("Amazon EC2"))
	if IsCloudInstance() {
		t.Fatal("IsCloudInstance() = true although network probes are disabled")
	}
}
