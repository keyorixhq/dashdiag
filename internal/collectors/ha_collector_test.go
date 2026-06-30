//go:build linux

package collectors

import (
	"encoding/xml"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// realHealthyCrmMon is verbatim `crm_mon --output-as=xml -1 -r` from a LIVE pacemaker
// 3.0.0 single-node cluster (Debian 13): one online node, one Started resource, fencing
// off. Guards the parser against the real schema (api-version 2.38).
const realHealthyCrmMon = `<pacemaker-result api-version="2.38" request="crm_mon --output-as=xml -1 -r">
  <summary>
    <stack type="corosync" pacemakerd-state="running"/>
    <current_dc present="true" with_quorum="true"/>
    <nodes_configured number="1"/>
    <resources_configured number="1" disabled="0" blocked="0"/>
    <cluster_options stonith-enabled="false" symmetric-cluster="true" no-quorum-policy="stop"/>
  </summary>
  <nodes>
    <node name="debian13-vm" id="1" online="true" standby="false" maintenance="false" unclean="false" type="member"/>
  </nodes>
  <resources>
    <resource id="dsd-dummy" resource_agent="ocf:pacemaker:Dummy" role="Started" active="true" failed="false" managed="true"/>
  </resources>
  <status code="0" message="OK"/>
</pacemaker-result>`

// realDegradedCrmMon — same schema, a 2-node cluster with quorum lost, one offline node,
// a configured fence device, a FAILED resource, and a Stopped resource.
const realDegradedCrmMon = `<pacemaker-result api-version="2.38">
  <summary>
    <current_dc present="true" with_quorum="false"/>
    <nodes_configured number="2"/>
    <cluster_options stonith-enabled="true"/>
  </summary>
  <nodes>
    <node name="node1" id="1" online="true" type="member"/>
    <node name="node2" id="2" online="false" type="member"/>
  </nodes>
  <resources>
    <resource id="fence-node1" resource_agent="stonith:fence_virt" role="Started" active="true" failed="false"/>
    <resource id="vip" resource_agent="ocf:heartbeat:IPaddr2" role="Stopped" active="false" failed="true"/>
    <resource id="webserver" resource_agent="ocf:heartbeat:apache" role="Stopped" active="false" failed="false"/>
  </resources>
</pacemaker-result>`

func TestApplyCrmMonHealthy(t *testing.T) {
	var x crmMonXML
	if err := xml.Unmarshal([]byte(realHealthyCrmMon), &x); err != nil {
		t.Fatalf("real crm_mon XML must parse: %v", err)
	}
	var info models.HAInfo
	applyCrmMon(&info, x)
	if info.NodesTotal != 1 || info.NodesOnline != 1 || len(info.OfflineNodes) != 0 {
		t.Errorf("nodes: total=%d online=%d offline=%v, want 1/1/none", info.NodesTotal, info.NodesOnline, info.OfflineNodes)
	}
	if info.ResourcesTotal != 1 || info.ResourcesStarted != 1 {
		t.Errorf("resources: total=%d started=%d, want 1/1", info.ResourcesTotal, info.ResourcesStarted)
	}
	if info.StonithEnabled || info.StonithDevices != 0 {
		t.Errorf("stonith: enabled=%v devices=%d, want false/0", info.StonithEnabled, info.StonithDevices)
	}
	if !info.QuorumKnown || !info.Quorate {
		t.Errorf("quorum from crm_mon with_quorum=true must be known+quorate, got known=%v quorate=%v", info.QuorumKnown, info.Quorate)
	}
}

func TestApplyCrmMonDegraded(t *testing.T) {
	var x crmMonXML
	if err := xml.Unmarshal([]byte(realDegradedCrmMon), &x); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var info models.HAInfo
	applyCrmMon(&info, x)
	if info.NodesTotal != 2 || info.NodesOnline != 1 || len(info.OfflineNodes) != 1 || info.OfflineNodes[0] != "node2" {
		t.Errorf("nodes: total=%d online=%d offline=%v, want 2/1/[node2]", info.NodesTotal, info.NodesOnline, info.OfflineNodes)
	}
	// fence-node1 is a stonith device (not a managed resource); vip failed; webserver stopped.
	if info.StonithDevices != 1 || !info.StonithEnabled {
		t.Errorf("stonith: enabled=%v devices=%d, want true/1", info.StonithEnabled, info.StonithDevices)
	}
	if info.ResourcesTotal != 2 || info.ResourcesStarted != 0 {
		t.Errorf("resources: total=%d started=%d, want 2/0", info.ResourcesTotal, info.ResourcesStarted)
	}
	if len(info.FailedResources) != 1 || info.FailedResources[0] != "vip" {
		t.Errorf("failed=%v, want [vip]", info.FailedResources)
	}
	if len(info.StoppedResources) != 1 || info.StoppedResources[0] != "webserver" {
		t.Errorf("stopped=%v, want [webserver]", info.StoppedResources)
	}
	if !info.QuorumKnown || info.Quorate {
		t.Errorf("with_quorum=false must be known+NOT quorate, got known=%v quorate=%v", info.QuorumKnown, info.Quorate)
	}
}
