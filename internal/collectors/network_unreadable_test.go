package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// DD-COLLECTOR-GAPS-1 Medium #6: when the interface list / TCP connection table
// cannot be read, the NetworkCollector must say so instead of returning an empty
// interface list and CloseWaitCount=0 as if the host were clean.
func TestNetworkCollector_UnreadableInterfacesAndConnectionsAreFlagged(t *testing.T) {
	// An empty replay bundle has no recorded gopsutil results: every cachedJSON
	// read fails, exactly like a /proc/net/* read failure on a live host.
	prev := SetSource(source.NewReplay(source.NewBundle()))
	t.Cleanup(func() { SetSource(prev) })

	raw, err := NewNetworkCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NetworkInfo)
	if !info.InterfacesUnreadable {
		t.Error("InterfacesUnreadable = false although the interface list could not be read")
	}
	if !info.ConnectionsUnreadable {
		t.Error("ConnectionsUnreadable = false although the TCP connection table could not be read")
	}
}

func TestNetworkCollector_ReadableInterfacesAndConnectionsAreNotFlagged(t *testing.T) {
	b := source.NewBundle()
	b.PutCached("gopsutil/net/interfaces", []byte("[]"))
	b.PutCached("gopsutil/net/iocounters", []byte("[]"))
	b.PutCached("gopsutil/net/connections/tcp", []byte("[]"))
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	raw, err := NewNetworkCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NetworkInfo)
	if info.InterfacesUnreadable || info.ConnectionsUnreadable {
		t.Errorf("flags set on a clean read: interfaces=%v connections=%v", info.InterfacesUnreadable, info.ConnectionsUnreadable)
	}
}
