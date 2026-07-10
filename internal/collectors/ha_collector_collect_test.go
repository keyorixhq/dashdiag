//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewHACollectorIdentity guards Name/Timeout wiring.
func TestNewHACollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewHACollector()
	if c == nil {
		t.Fatal("NewHACollector() returned nil")
	}
	if c.Name() != "HACluster" {
		t.Errorf("Name() = %q, want HACluster", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
}

// TestHAAvailable guards the three-binary OR gate: present via any one of
// crm_mon / pacemakerd / corosync-quorumtool must report available; none
// present must report unavailable.
func TestHAAvailable(t *testing.T) {
	t.Run("crm_mon present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/crm_mon": []byte("/usr/sbin/crm_mon"),
		}, nil, nil)
		if !HAAvailable() {
			t.Error("expected true when crm_mon is present")
		}
	})

	t.Run("pacemakerd present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/pacemakerd": []byte("/usr/sbin/pacemakerd"),
		}, nil, nil)
		if !HAAvailable() {
			t.Error("expected true when pacemakerd is present")
		}
	})

	t.Run("corosync-quorumtool present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/corosync-quorumtool": []byte("/usr/sbin/corosync-quorumtool"),
		}, nil, nil)
		if !HAAvailable() {
			t.Error("expected true when corosync-quorumtool is present")
		}
	})

	t.Run("none present", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{}, nil, nil)
		if HAAvailable() {
			t.Error("expected false when none of the cluster binaries are present")
		}
	})
}

// TestHACollector_Collect_NotAvailable guards the gate-off path: no cluster
// stack installed must return an empty HAInfo{} (Available=false) without
// running any further commands.
func TestHACollector_Collect_NotAvailable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{}, nil, nil)

	c := NewHACollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAInfo)
	if info.Available {
		t.Errorf("expected Available=false, got %+v", info)
	}
}

// TestHACollector_Collect_InstalledButNotRunning guards the
// installed-but-stopped path: the stack is present but corosync/pacemaker
// aren't active — Available=true, Running=false, and no crm_mon/quorumtool
// commands should be needed to reach a conclusion.
func TestHACollector_Collect_InstalledButNotRunning(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/crm_mon": []byte("/usr/sbin/crm_mon"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "corosync"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "pacemaker"}, "inactive\n", 3)
	})

	c := NewHACollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAInfo)
	if !info.Available {
		t.Error("expected Available=true (stack installed)")
	}
	if info.Running {
		t.Error("expected Running=false (units inactive)")
	}
}

// TestHACollector_Collect_RunningQuorateHealthy exercises the full running
// path: corosync+pacemaker active, quorumtool reports quorate, crm_mon XML
// parses into a healthy single-node cluster.
func TestHACollector_Collect_RunningQuorateHealthy(t *testing.T) {
	crmXML := `<pacemaker-result api-version="2.38">
  <summary>
    <current_dc present="true" with_quorum="true"/>
    <nodes_configured number="1"/>
    <cluster_options stonith-enabled="false"/>
  </summary>
  <nodes>
    <node name="node1" id="1" online="true" type="member"/>
  </nodes>
  <resources>
    <resource id="dummy" resource_agent="ocf:pacemaker:Dummy" role="Started" active="true" failed="false"/>
  </resources>
</pacemaker-result>`

	withCombinedFixture(t, map[string][]byte{
		"lookpath/crm_mon": []byte("/usr/sbin/crm_mon"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "corosync"}, "active\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "pacemaker"}, "active\n", 0)
		b.PutCmd("corosync-quorumtool", []string{"-s"}, "Quorate:          Yes\n", 0)
		b.PutCmd("crm_mon", []string{"--output-as=xml", "-1", "-r"}, crmXML, 0)
	})

	c := NewHACollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAInfo)
	if !info.Available || !info.Running {
		t.Fatalf("expected Available=true Running=true, got %+v", info)
	}
	if !info.QuorumKnown || !info.Quorate {
		t.Errorf("expected quorum known+quorate from corosync-quorumtool, got known=%v quorate=%v", info.QuorumKnown, info.Quorate)
	}
	if !info.StatusReadable {
		t.Error("expected StatusReadable=true when crm_mon XML parses")
	}
	if info.NodesOnline != 1 || info.NodesTotal != 1 {
		t.Errorf("expected 1/1 nodes online/total, got %d/%d", info.NodesOnline, info.NodesTotal)
	}
	if info.ResourcesStarted != 1 {
		t.Errorf("expected 1 started resource, got %d", info.ResourcesStarted)
	}
}

// TestHACollector_Collect_QuorumUnknownFallsBackToCrmMon guards the fallback:
// when corosync-quorumtool fails (non-root, can't read the CIB context), the
// quorum state should still be recovered from crm_mon's with_quorum attribute.
func TestHACollector_Collect_QuorumUnknownFallsBackToCrmMon(t *testing.T) {
	crmXML := `<pacemaker-result api-version="2.38">
  <summary>
    <current_dc present="true" with_quorum="false"/>
    <nodes_configured number="2"/>
    <cluster_options stonith-enabled="true"/>
  </summary>
  <nodes>
    <node name="node1" id="1" online="true" type="member"/>
    <node name="node2" id="2" online="false" type="member"/>
  </nodes>
  <resources/>
</pacemaker-result>`

	withCombinedFixture(t, map[string][]byte{
		"lookpath/pacemakerd": []byte("/usr/sbin/pacemakerd"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "corosync"}, "active\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "pacemaker"}, "active\n", 0)
		b.PutCmd("corosync-quorumtool", []string{"-s"}, "", 1) // fails (non-root)
		b.PutCmd("crm_mon", []string{"--output-as=xml", "-1", "-r"}, crmXML, 0)
	})

	c := NewHACollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAInfo)
	if !info.QuorumKnown || info.Quorate {
		t.Errorf("expected quorum known(via crm_mon)+NOT quorate, got known=%v quorate=%v", info.QuorumKnown, info.Quorate)
	}
	if len(info.OfflineNodes) != 1 || info.OfflineNodes[0] != "node2" {
		t.Errorf("expected node2 offline, got %+v", info.OfflineNodes)
	}
}

// TestHACollector_Collect_CrmMonUnreadable guards the non-root path: crm_mon
// fails (CIB is root-only) — StatusReadable must stay false rather than
// implying a healthy cluster, and Collect must not error.
func TestHACollector_Collect_CrmMonUnreadable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/crm_mon": []byte("/usr/sbin/crm_mon"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "corosync"}, "active\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "pacemaker"}, "active\n", 0)
		b.PutCmd("corosync-quorumtool", []string{"-s"}, "Quorate:          Yes\n", 0)
		b.PutCmd("crm_mon", []string{"--output-as=xml", "-1", "-r"}, "", 1) // permission denied
	})

	c := NewHACollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAInfo)
	if info.StatusReadable {
		t.Error("expected StatusReadable=false when crm_mon fails/is unreadable")
	}
	if !info.QuorumKnown || !info.Quorate {
		t.Errorf("quorum from corosync-quorumtool should still be recorded, got known=%v quorate=%v", info.QuorumKnown, info.Quorate)
	}
}

// TestHACollector_Collect_CrmMonMalformedXML guards the XML-unmarshal-failure
// branch: garbage output must not error the collector, just leave
// StatusReadable false.
func TestHACollector_Collect_CrmMonMalformedXML(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/crm_mon": []byte("/usr/sbin/crm_mon"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "corosync"}, "active\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "pacemaker"}, "active\n", 0)
		b.PutCmd("corosync-quorumtool", []string{"-s"}, "", 1)
		b.PutCmd("crm_mon", []string{"--output-as=xml", "-1", "-r"}, "<not valid xml", 0)
	})

	c := NewHACollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAInfo)
	if info.StatusReadable {
		t.Error("expected StatusReadable=false on malformed XML")
	}
}
