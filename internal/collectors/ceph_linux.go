//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
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
		if _, statErr := os.Stat("/etc/ceph/ceph.conf"); statErr == nil {
			info.Configured = true
			info.StatusReason = "ceph health detail failed — cluster unreachable"
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
	if err := json.Unmarshal([]byte(out), &h); err == nil {
		info.Health = h.Status
		for _, v := range h.Checks {
			info.Summary = append(info.Summary, v.Summary.Message)
		}
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
	_, err := exec.LookPath("ceph")
	return err == nil
}
