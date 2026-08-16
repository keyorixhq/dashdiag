//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// withOCIFixture needs both dimensions the shared withCombinedFixture (see
// security_linux_source_test.go) provides: imdsGet and ociIMDSv1Open's raw
// probe both go through Cached, and collectNICDrivers resolves
// /sys/class/net/<if>/device/driver symlinks via Readlink.
func withOCIFixture(t *testing.T, cached map[string][]byte, links map[string]string, seed func(b *source.Bundle)) {
	t.Helper()
	withCombinedFixture(t, cached, links, seed)
}

const ociInstanceDocJSON = `{"id":"ocid1.instance.oc1.phx.abc","shape":"VM.Standard.A1.Flex","canonicalRegionName":"us-phoenix-1","availabilityDomain":"Bdcu:PHX-AD-1"}`

func TestOCICollectorIdentity(t *testing.T) {
	c := NewOCICollector()
	if c == nil {
		t.Fatal("NewOCICollector returned nil")
	}
	if c.Name() != "OCI" {
		t.Errorf("Name() = %q, want OCI", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestOCIGuestAvailable_True(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/chassis_asset_tag", []byte("OracleCloud.com\n"))
	})
	if !OCIGuestAvailable() {
		t.Error("OCIGuestAvailable() = false, want true")
	}
}

func TestOCIGuestAvailable_False(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/chassis_asset_tag", []byte("Amazon EC2\n"))
	})
	if OCIGuestAvailable() {
		t.Error("OCIGuestAvailable() = true, want false")
	}
}

func TestOciInstanceDocRead_Success(t *testing.T) {
	withOCIFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/opc/v2/instance/#Authorization=Bearer Oracle": []byte(ociInstanceDocJSON),
	}, nil, nil)
	doc := ociInstanceDocRead(context.Background())
	if doc == nil {
		t.Fatal("ociInstanceDocRead() = nil, want a populated doc")
	}
	if doc.Shape != "VM.Standard.A1.Flex" || doc.CanonicalRegionName != "us-phoenix-1" || doc.AvailabilityDomain != "Bdcu:PHX-AD-1" {
		t.Errorf("doc = %+v, unexpected fields", doc)
	}
}

func TestOciInstanceDocRead_Unreachable(t *testing.T) {
	withOCIFixture(t, nil, nil, nil)
	if doc := ociInstanceDocRead(context.Background()); doc != nil {
		t.Errorf("ociInstanceDocRead() = %+v, want nil when IMDS is unreachable", doc)
	}
}

func TestOciInstanceDocRead_BadJSON(t *testing.T) {
	withOCIFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/opc/v2/instance/#Authorization=Bearer Oracle": []byte("not json"),
	}, nil, nil)
	if doc := ociInstanceDocRead(context.Background()); doc != nil {
		t.Errorf("ociInstanceDocRead() = %+v, want nil on unparseable body", doc)
	}
}

func TestOciInstanceMeta_Found(t *testing.T) {
	withOCIFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/opc/v2/instance/#Authorization=Bearer Oracle": []byte(ociInstanceDocJSON),
	}, nil, nil)
	shape, region, ad := ociInstanceMeta(context.Background())
	if shape != "VM.Standard.A1.Flex" || region != "us-phoenix-1" || ad != "Bdcu:PHX-AD-1" {
		t.Errorf("ociInstanceMeta() = (%q,%q,%q), unexpected", shape, region, ad)
	}
}

func TestOciInstanceMeta_NotFound(t *testing.T) {
	withOCIFixture(t, nil, nil, nil)
	shape, region, ad := ociInstanceMeta(context.Background())
	if shape != "" || region != "" || ad != "" {
		t.Errorf("ociInstanceMeta() = (%q,%q,%q), want all empty", shape, region, ad)
	}
}

func TestOciIMDSv1Open_Unreachable(t *testing.T) {
	withOCIFixture(t, nil, nil, nil)
	checked, open := ociIMDSv1Open(context.Background())
	if checked || open {
		t.Errorf("ociIMDSv1Open() = (%v,%v), want (false,false) when unreachable", checked, open)
	}
}

func TestOciIMDSv1Open_OpenAndBlocked(t *testing.T) {
	withOCIFixture(t, map[string][]byte{"oci-imdsv1-probe": []byte("open")}, nil, nil)
	checked, open := ociIMDSv1Open(context.Background())
	if !checked || !open {
		t.Errorf("ociIMDSv1Open() = (%v,%v), want (true,true)", checked, open)
	}

	withOCIFixture(t, map[string][]byte{"oci-imdsv1-probe": []byte("blocked")}, nil, nil)
	checked, open = ociIMDSv1Open(context.Background())
	if !checked || open {
		t.Errorf("ociIMDSv1Open() = (%v,%v), want (true,false)", checked, open)
	}
}

func TestOciServiceState_Found(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "oracle-cloud-agent.service", "-p", "LoadState,ActiveState", "--value"},
			"loaded\nactive\n", 0)
	})
	loadState, activeState := ociServiceState(context.Background(), "oracle-cloud-agent.service")
	if loadState != "loaded" || activeState != "active" {
		t.Errorf("ociServiceState() = (%q,%q), want (loaded,active)", loadState, activeState)
	}
}

func TestOciServiceState_NotFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "bogus.service", "-p", "LoadState,ActiveState", "--value"},
			"not-found\ninactive\n", 0)
	})
	loadState, activeState := ociServiceState(context.Background(), "bogus.service")
	if loadState != "not-found" || activeState != "inactive" {
		t.Errorf("ociServiceState() = (%q,%q), want (not-found,inactive)", loadState, activeState)
	}
}

func TestOciServiceState_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"show", "x.service", "-p", "LoadState,ActiveState", "--value"})
	})
	loadState, activeState := ociServiceState(context.Background(), "x.service")
	if loadState != "" || activeState != "" {
		t.Errorf("ociServiceState() = (%q,%q), want empty on command failure", loadState, activeState)
	}
}

// TestOciServiceState_TooFewLines guards the len(lines) < 2 defensive branch:
// systemctl show returning a single line (garbled/truncated output) must not
// be indexed into as if both LoadState and ActiveState were present.
func TestOciServiceState_TooFewLines(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "y.service", "-p", "LoadState,ActiveState", "--value"},
			"loaded\n", 0)
	})
	loadState, activeState := ociServiceState(context.Background(), "y.service")
	if loadState != "" || activeState != "" {
		t.Errorf("ociServiceState() = (%q,%q), want empty when output has fewer than 2 lines", loadState, activeState)
	}
}

func TestOciAgentState_InstalledAndRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "oracle-cloud-agent.service", "-p", "LoadState,ActiveState", "--value"},
			"loaded\nactive\n", 0)
		b.PutCmd("systemctl", []string{"show", "oracle-cloud-agent-updater.service", "-p", "LoadState,ActiveState", "--value"},
			"loaded\nactive\n", 0)
	})
	checked, installed, running, updaterRunning := ociAgentState(context.Background())
	if !checked || !installed || !running || !updaterRunning {
		t.Errorf("ociAgentState() = (%v,%v,%v,%v), want all true", checked, installed, running, updaterRunning)
	}
}

func TestOciAgentState_NotSystemd(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"show", "oracle-cloud-agent.service", "-p", "LoadState,ActiveState", "--value"})
	})
	checked, installed, running, updaterRunning := ociAgentState(context.Background())
	if checked || installed || running || updaterRunning {
		t.Errorf("ociAgentState() = (%v,%v,%v,%v), want all false", checked, installed, running, updaterRunning)
	}
}

func TestOciAgentState_InstalledButNotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "oracle-cloud-agent.service", "-p", "LoadState,ActiveState", "--value"},
			"loaded\ninactive\n", 0)
		b.PutCmd("systemctl", []string{"show", "oracle-cloud-agent-updater.service", "-p", "LoadState,ActiveState", "--value"},
			"not-found\ninactive\n", 0)
	})
	checked, installed, running, updaterRunning := ociAgentState(context.Background())
	if !checked || !installed || running || updaterRunning {
		t.Errorf("ociAgentState() = (%v,%v,%v,%v), want (true,true,false,false)", checked, installed, running, updaterRunning)
	}
}

func TestOciTimeSynced_True(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("chronyc", []string{"sources"},
			"MS Name/IP address         Stratum Poll Reach LastRx Last sample\n"+
				"^* 169.254.169.254               3   6   377    10  +100us[+120us] +/-  500us\n", 0)
	})
	if !ociTimeSynced(context.Background()) {
		t.Error("ociTimeSynced() = false, want true")
	}
}

func TestOciTimeSynced_NotSelected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("chronyc", []string{"sources"},
			"^+ 169.254.169.254               3   6   377    10  +100us[+120us] +/-  500us\n", 0)
	})
	if ociTimeSynced(context.Background()) {
		t.Error("ociTimeSynced() = true, want false (candidate '^+', not selected '^*')")
	}
}

func TestOciTimeSynced_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("chronyc", []string{"sources"})
	})
	if ociTimeSynced(context.Background()) {
		t.Error("ociTimeSynced() = true, want false when chronyc is absent")
	}
}

func TestOciVNICRingStats_Found(t *testing.T) {
	withOCIFixture(t, nil, map[string]string{
		"/sys/class/net/ens3/device/driver": "/sys/bus/virtio/drivers/virtio_net",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"ens3"})
		b.PutCmd("ethtool", []string{"-S", "ens3"}, "     rx_drops: 4\n     tx_tx_timeouts: 1\n", 0)
	})
	checked, vnics := ociVNICRingStats(context.Background())
	if !checked {
		t.Fatal("checked = false, want true")
	}
	if len(vnics) != 1 || vnics[0].Iface != "ens3" || vnics[0].Driver != "virtio_net" ||
		vnics[0].RxDrops != 4 || vnics[0].TxTimeouts != 1 {
		t.Errorf("vnics = %+v, unexpected", vnics)
	}
}

func TestOciVNICRingStats_NoVirtioNIC(t *testing.T) {
	withOCIFixture(t, nil, map[string]string{
		"/sys/class/net/eth0/device/driver": "/sys/bus/pci/drivers/e1000",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0"})
	})
	checked, vnics := ociVNICRingStats(context.Background())
	if checked || vnics != nil {
		t.Errorf("ociVNICRingStats() = (%v,%v), want (false,nil) with no virtio_net NIC", checked, vnics)
	}
}

func TestOciVNICRingStats_EthtoolFails(t *testing.T) {
	withOCIFixture(t, nil, map[string]string{
		"/sys/class/net/ens3/device/driver": "/sys/bus/virtio/drivers/virtio_net",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"ens3"})
		b.PutCmdNotFound("ethtool", []string{"-S", "ens3"})
	})
	checked, vnics := ociVNICRingStats(context.Background())
	if checked || vnics != nil {
		t.Errorf("ociVNICRingStats() = (%v,%v), want (false,nil) when ethtool is absent", checked, vnics)
	}
}

func TestSortOCIVNICs(t *testing.T) {
	v := []models.OCIVNIC{{Iface: "ens5"}, {Iface: "ens3"}, {Iface: "ens4"}}
	sortOCIVNICs(v)
	want := []string{"ens3", "ens4", "ens5"}
	for i, w := range want {
		if v[i].Iface != w {
			t.Errorf("sortOCIVNICs()[%d] = %q, want %q", i, v[i].Iface, w)
		}
	}
}

func TestSortOCIVNICs_EmptyAndSingle(t *testing.T) {
	sortOCIVNICs(nil) // must not panic
	v := []models.OCIVNIC{{Iface: "ens3"}}
	sortOCIVNICs(v)
	if v[0].Iface != "ens3" {
		t.Errorf("single-element sort mutated value: %+v", v)
	}
}

// TestOCICollector_Collect_FullHappyPath drives the entire Collect() pipeline:
// instance metadata, IMDSv1 posture, agent state, OCI-time-sync configured AND
// synced, and one virtio_net VNIC with ring drops.
func TestOCICollector_Collect_FullHappyPath(t *testing.T) {
	withOCIFixture(t,
		map[string][]byte{
			"imds/http://169.254.169.254/opc/v2/instance/#Authorization=Bearer Oracle": []byte(ociInstanceDocJSON),
			"oci-imdsv1-probe": []byte("blocked"),
		},
		map[string]string{
			"/sys/class/net/ens3/device/driver": "/sys/bus/virtio/drivers/virtio_net",
		},
		func(b *source.Bundle) {
			b.PutCmd("systemctl", []string{"show", "oracle-cloud-agent.service", "-p", "LoadState,ActiveState", "--value"},
				"loaded\nactive\n", 0)
			b.PutCmd("systemctl", []string{"show", "oracle-cloud-agent-updater.service", "-p", "LoadState,ActiveState", "--value"},
				"loaded\nactive\n", 0)
			b.PutFile("/etc/chrony.conf", []byte("server 169.254.169.254 iburst\n"))
			b.PutCmd("chronyc", []string{"sources"}, "^* 169.254.169.254   3 6 377 10 +100us\n", 0)
			b.PutDir("/sys/class/net", []string{"ens3"})
			b.PutCmd("ethtool", []string{"-S", "ens3"}, "     rx_drops: 2\n     tx_tx_timeouts: 0\n", 0)
		},
	)

	c := NewOCICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.OCIInfo)

	if !info.IsOCI {
		t.Error("IsOCI = false, want true")
	}
	if info.Shape != "VM.Standard.A1.Flex" || info.Region != "us-phoenix-1" || info.AvailabilityDomain != "Bdcu:PHX-AD-1" {
		t.Errorf("Shape/Region/AD = %q/%q/%q, unexpected", info.Shape, info.Region, info.AvailabilityDomain)
	}
	if !info.IMDSChecked || info.IMDSv1Open {
		t.Errorf("IMDSChecked=%v IMDSv1Open=%v, want (true,false)", info.IMDSChecked, info.IMDSv1Open)
	}
	if !info.AgentChecked || !info.AgentInstalled || !info.AgentRunning || !info.AgentUpdaterRunning {
		t.Errorf("agent fields = %+v, want all true", info)
	}
	if !info.TimeSyncChecked || !info.UsesOCITimeSync || !info.TimeSynced {
		t.Errorf("TimeSyncChecked=%v UsesOCITimeSync=%v TimeSynced=%v, want all true",
			info.TimeSyncChecked, info.UsesOCITimeSync, info.TimeSynced)
	}
	if !info.VNICChecked || len(info.VNICs) != 1 || info.VNICs[0].Iface != "ens3" || info.VNICs[0].RxDrops != 2 {
		t.Errorf("VNICChecked=%v VNICs=%+v, unexpected", info.VNICChecked, info.VNICs)
	}
}

// TestOCICollector_Collect_NotConfiguredForOCITimeSync verifies TimeSynced is
// never probed (chronyc not invoked) when time sync isn't pointed at OCI at all.
func TestOCICollector_Collect_NotConfiguredForOCITimeSync(t *testing.T) {
	withOCIFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutFile("/etc/chrony.conf", []byte("pool 2.pool.ntp.org iburst\n"))
		b.PutCmdNotFound("systemctl", []string{"show", "oracle-cloud-agent.service", "-p", "LoadState,ActiveState", "--value"})
		b.PutDir("/sys/class/net", []string{})
	})

	c := NewOCICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.OCIInfo)
	if !info.TimeSyncChecked || info.UsesOCITimeSync || info.TimeSynced {
		t.Errorf("TimeSyncChecked=%v UsesOCITimeSync=%v TimeSynced=%v, want (true,false,false)",
			info.TimeSyncChecked, info.UsesOCITimeSync, info.TimeSynced)
	}
}
