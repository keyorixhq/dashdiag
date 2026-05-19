//go:build linux

package collectors

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// IsLVMPresent returns true when LVM tools are installed on this host.
func IsLVMPresent() bool {
	_, err := runCmd(context.Background(), "lvs", "--version")
	return err == nil
}

// LVMCollector checks LVM volume group free space, thin pool usage,
// and snapshot health. Linux-only; silent no-op when lvm2 is not installed.
type LVMCollector struct{}

func NewLVMCollector() *LVMCollector { return &LVMCollector{} }

func (c *LVMCollector) Name() string           { return "LVM" }
func (c *LVMCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *LVMCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.LVMInfo{}

	// lvm2 not installed — silent OK
	if !IsLVMPresent() {
		return info, nil
	}

	// --- Volume groups ---
	vgsOut, err := runCmd(ctx, "vgs", "--noheadings", "--nosuffix", "--units", "g",
		"-o", "vg_name,vg_size,vg_free,vg_attr")
	if err == nil {
		info.VGs = parseVGs(vgsOut)
	}

	// --- PV health: count missing PVs per VG ---
	pvsOut, err := runCmd(ctx, "pvs", "--noheadings", "-o", "vg_name,pv_attr")
	if err == nil {
		mergeMissingPVs(pvsOut, info.VGs)
	}

	// --- LVs: thin pools and snapshots ---
	lvsOut, err := runCmd(ctx, "lvs", "--noheadings", "--nosuffix", "--units", "g",
		"-o", "lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size")
	if err == nil {
		info.ThinPools, info.Snapshots = parseLVs(lvsOut)
	}

	// --- Mark VGs with at least one mounted LV ---
	// VGs with no mounted LVs are leftover/inactive (e.g. old OS install on
	// a second drive). These should be INFO not CRIT when full.
	mergeMountedLVs(info.VGs)

	// RAID/mirror LV health — copy_percent and lv_attr sync/degraded flags
	raidOut, _ := runCmd(ctx, "lvs", "--noheadings", "--nosuffix", "--units", "g",
		"-o", "lv_name,vg_name,lv_attr,lv_size,copy_percent")
	if raidOut != "" {
		info.RaidLVs = parseLVMRaid(raidOut)
	}

	return info, nil
}

// parseLVMRaid extracts mirror/RAID LVs from lvs output.
// lv_attr[0]: 'm'=mirror, 'r'=raid; lv_attr[8]: 'p'=partial (degraded); lv_attr[9]: 'r'=resyncing
func parseLVMRaid(out string) []models.LVMRaidLV {
	var result []models.LVMRaidLV
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name, vg, attr := fields[0], fields[1], fields[2]
		if len(attr) < 10 {
			continue
		}
		lvType := attr[0]
		if lvType != 'm' && lvType != 'r' {
			continue
		}
		sizeGB, _ := strconv.ParseFloat(fields[3], 64)
		syncPct := 100.0 // default: fully synced
		if len(fields) > 4 && fields[4] != "" {
			if v, err := strconv.ParseFloat(fields[4], 64); err == nil {
				syncPct = v
			}
		}
		lv := models.LVMRaidLV{
			Name:      name,
			VG:        vg,
			SizeGB:    sizeGB,
			SyncPct:   syncPct,
			Degraded:  len(attr) > 8 && attr[8] == 'p',
			Resyncing: len(attr) > 9 && attr[9] == 'r',
		}
		if lvType == 'm' {
			lv.Type = "mirror"
		} else {
			lv.Type = "raid"
		}
		result = append(result, lv)
	}
	return result
}

// mergeMountedLVs reads /proc/mounts to find which VGs have at least one
// LV currently mounted. A VG with no mounted LVs is leftover/inactive —
// typically a previous OS install on a different drive — and should not
// trigger CRIT alerts just because it's full.
func mergeMountedLVs(vgs []models.LVMVG) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return
	}
	// /proc/mounts lines: "/dev/mapper/ol-root / ext4 rw,..."
	// LVM devices appear as /dev/mapper/<vg>-<lv> or /dev/<vg>/<lv>
	mountedVGs := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		dev := fields[0]
		// /dev/mapper/vgname-lvname
		if strings.HasPrefix(dev, "/dev/mapper/") {
			name := strings.TrimPrefix(dev, "/dev/mapper/")
			if dashIdx := strings.Index(name, "-"); dashIdx > 0 {
				mountedVGs[name[:dashIdx]] = true
			}
		}
		// /dev/vgname/lvname
		if strings.HasPrefix(dev, "/dev/") {
			parts := strings.SplitN(strings.TrimPrefix(dev, "/dev/"), "/", 2)
			if len(parts) == 2 {
				mountedVGs[parts[0]] = true
			}
		}
	}
	for i, vg := range vgs {
		if mountedVGs[vg.Name] {
			vgs[i].HasMountedLV = true
		}
	}
}
