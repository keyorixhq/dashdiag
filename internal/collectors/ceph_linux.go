//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type CephCollector struct{}

func NewCephCollector() *CephCollector          { return &CephCollector{} }
func (c *CephCollector) Name() string           { return "Ceph" }
func (c *CephCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *CephCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.CephInfo{}

	out, err := runCmd(ctx, "ceph", "health", "detail", "--format", "json")
	if err != nil {
		// `ceph health` failed. Distinguish a host that merely has the client
		// binary (no cluster — stay silent) from one configured for a cluster it
		// can no longer reach (a real outage that must be flagged, not hidden).
		// /etc/ceph/ceph.conf — a symlink to /etc/pve/ceph.conf on Proxmox
		// hyperconverged — is the "this node is part of a cluster" signal.
		if fileExists("/etc/ceph/ceph.conf") {
			info.Configured = true
			info.StatusReason = "ceph health detail failed — cluster unreachable"
			// The admin keyring (/etc/ceph/ceph.client.admin.keyring) is root-only, so
			// an unprivileged `ceph health` fails on a perfectly healthy node. Don't let
			// that escalate to a false "cluster unreachable" CRIT — mark it needs-root so
			// the verdict degrades to "could not verify" (the run-as-both rule).
			if os.Geteuid() != 0 {
				info.NeedsRoot = true
				info.StatusReason = "ceph health needs root (admin keyring is root-only) — cluster state not verified"
			}
		}
		return info, nil
	}
	info.Available = true

	var h struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Summary struct{ Message string } `json:"summary"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &h); err == nil && h.Status != "" {
		info.Health = h.Status
		for _, v := range h.Checks {
			info.Summary = append(info.Summary, v.Summary.Message)
		}
	} else {
		// `ceph health detail` exited 0 but its stdout wasn't parseable health JSON
		// (empty, a leading deprecation/WARNING banner before the JSON, or an
		// unexpected shape). Leaving Health="" reads as a clean cluster in checkCeph
		// (matches neither HEALTH_ERR nor HEALTH_WARN) — a false-OK on a cluster we
		// never actually read. Mark it unknown so the verdict says so.
		info.Health = "HEALTH_UNKNOWN"
	}

	// OSD stats
	osdOut, err := runCmd(ctx, "ceph", "osd", "stat", "--format", "json")
	if err == nil {
		var s struct {
			NumOSDs   int `json:"num_osds"`
			NumUpOSDs int `json:"num_up_osds"`
			NumInOSDs int `json:"num_in_osds"`
		}
		if err := json.Unmarshal([]byte(osdOut), &s); err == nil {
			info.OSDTotal = s.NumOSDs
			info.OSDUp = s.NumUpOSDs
			info.OSDIn = s.NumInOSDs
		}
	}
	return info, nil
}

func IsCephPresent() bool {
	_, err := lookPath("ceph")
	return err == nil
}
