//go:build linux

package collectors

import (
	"context"
	"encoding/xml"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HACollector reports Pacemaker/Corosync high-availability cluster health. Gated on the
// cluster stack being installed (crm_mon / pacemakerd / corosync), so it's silent on
// every non-cluster host.
type HACollector struct{}

func NewHACollector() *HACollector            { return &HACollector{} }
func (c *HACollector) Name() string           { return "HACluster" }
func (c *HACollector) Timeout() time.Duration { return 10 * time.Second }

// HAAvailable gates inclusion on the Pacemaker/Corosync stack being present.
func HAAvailable() bool {
	return hasCmd("crm_mon") || hasCmd("pacemakerd") || hasCmd("corosync-quorumtool")
}

// crmMonXML mirrors the stable parts of `crm_mon --output-as=xml` (pacemaker 2.x).
type crmMonXML struct {
	Summary struct {
		CurrentDC struct {
			WithQuorum string `xml:"with_quorum,attr"`
		} `xml:"current_dc"`
		NodesConfigured struct {
			Number int `xml:"number,attr"`
		} `xml:"nodes_configured"`
		ClusterOptions struct {
			StonithEnabled string `xml:"stonith-enabled,attr"`
		} `xml:"cluster_options"`
	} `xml:"summary"`
	Nodes struct {
		Node []struct {
			Name   string `xml:"name,attr"`
			Online string `xml:"online,attr"`
		} `xml:"node"`
	} `xml:"nodes"`
	Resources crmMonResources `xml:"resources"`
}

// crmMonResource is a single <resource> element, wherever it appears — a bare top-level
// resource, or nested inside a <clone>, <group>, or <bundle><replica>.
type crmMonResource struct {
	ID            string `xml:"id,attr"`
	ResourceAgent string `xml:"resource_agent,attr"`
	Role          string `xml:"role,attr"`
	Active        string `xml:"active,attr"`
	Failed        string `xml:"failed,attr"`
}

type crmMonGroup struct {
	Resource []crmMonResource `xml:"resource"`
}

type crmMonReplica struct {
	Resource []crmMonResource `xml:"resource"`
}

type crmMonBundle struct {
	Replica []crmMonReplica `xml:"replica"`
}

type crmMonClone struct {
	Resource []crmMonResource `xml:"resource"`
	Group    []crmMonGroup    `xml:"group"`
}

// crmMonResources mirrors <resources>. Pacemaker nests multi-instance/grouped resources
// inside <clone>, <group>, and <bundle><replica> wrappers — encoding/xml only matches
// direct children, so a bare `Resource []struct{...}` silently drops every resource that
// isn't a top-level singleton. flatten() recovers the full resource list regardless of
// nesting.
type crmMonResources struct {
	Resource []crmMonResource `xml:"resource"`
	Clone    []crmMonClone    `xml:"clone"`
	Group    []crmMonGroup    `xml:"group"`
	Bundle   []crmMonBundle   `xml:"bundle"`
}

func (r crmMonResources) flatten() []crmMonResource {
	all := append([]crmMonResource{}, r.Resource...)
	for _, cl := range r.Clone {
		all = append(all, cl.Resource...)
		for _, g := range cl.Group {
			all = append(all, g.Resource...)
		}
	}
	for _, g := range r.Group {
		all = append(all, g.Resource...)
	}
	for _, b := range r.Bundle {
		for _, rep := range b.Replica {
			all = append(all, rep.Resource...)
		}
	}
	return all
}

func (c *HACollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.HAInfo{}
	if !HAAvailable() {
		return info, nil
	}
	info.Available = true

	// Running == both daemons active. A stack installed but stopped means this node is
	// not part of a live cluster (handled honestly by the heuristic).
	info.Running = unitActive(ctx, "corosync") && unitActive(ctx, "pacemaker")
	if !info.Running {
		return info, nil
	}

	// Quorum, read directly from corosync (the authority on partition membership).
	if out, err := runCmdOutput(ctx, "corosync-quorumtool", "-s"); err == nil && out != "" {
		info.QuorumKnown = true
		low := strings.ToLower(out)
		// "Quorate:          Yes" / "No"
		for _, line := range strings.Split(low, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "quorate:") {
				info.Quorate = strings.Contains(line, "yes")
			}
		}
	}

	// Nodes / resources / fencing from crm_mon XML (stable, structured). crm_mon reads
	// the CIB, which is root-only — a non-root run can't read it, so StatusReadable stays
	// false and the heuristic reports "couldn't verify" instead of implying healthy.
	out, err := runCmdOutput(ctx, "crm_mon", "--output-as=xml", "-1", "-r")
	if err != nil || strings.TrimSpace(out) == "" {
		return info, nil
	}
	var x crmMonXML
	if xml.Unmarshal([]byte(out), &x) != nil {
		return info, nil
	}
	info.StatusReadable = true
	applyCrmMon(info, x)
	return info, nil
}

// applyCrmMon maps parsed crm_mon XML onto the node/resource/fencing fields of info.
// Split out so the parser is unit-tested against real pacemaker XML.
func applyCrmMon(info *models.HAInfo, x crmMonXML) {
	info.NodesTotal = x.Summary.NodesConfigured.Number
	info.StonithEnabled = x.Summary.ClusterOptions.StonithEnabled == "true"
	// Trust corosync-quorumtool when it answered; otherwise fall back to crm_mon's own
	// quorum view so quorum is still known.
	if !info.QuorumKnown && x.Summary.CurrentDC.WithQuorum != "" {
		info.QuorumKnown = true
		info.Quorate = x.Summary.CurrentDC.WithQuorum == "true"
	}
	for _, n := range x.Nodes.Node {
		if n.Online == "true" {
			info.NodesOnline++
		} else {
			info.OfflineNodes = append(info.OfflineNodes, n.Name)
		}
	}
	for _, r := range x.Resources.flatten() {
		if strings.HasPrefix(r.ResourceAgent, "stonith:") {
			info.StonithDevices++
			continue
		}
		info.ResourcesTotal++
		switch {
		case r.Failed == "true":
			info.FailedResources = append(info.FailedResources, r.ID)
		case r.Role == "Started" || r.Active == "true":
			info.ResourcesStarted++
		case r.Role == "Stopped":
			info.StoppedResources = append(info.StoppedResources, r.ID)
		}
	}
}
