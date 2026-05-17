//go:build linux

package collectors

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// LVMCollector checks LVM volume group free space, thin pool usage,
// and snapshot health. Linux-only; silent no-op when lvm2 is not installed.
type LVMCollector struct{}

func NewLVMCollector() *LVMCollector { return &LVMCollector{} }

func (c *LVMCollector) Name() string           { return "LVM" }
func (c *LVMCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *LVMCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.LVMInfo{}

	// lvm2 not installed — silent OK
	if _, err := exec.LookPath("lvs"); err != nil {
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

	return info, nil
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
func parseVGs(out string) []models.LVMVG {
	var vgs []models.LVMVG
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		vg := models.LVMVG{Name: fields[0]}
		vg.SizeGB, _ = strconv.ParseFloat(fields[1], 64)
		vg.FreeGB, _ = strconv.ParseFloat(fields[2], 64)
		if vg.SizeGB > 0 {
			vg.FreePct = vg.FreeGB / vg.SizeGB * 100
		}
		vgs = append(vgs, vg)
	}
	return vgs
}

// mergeMissingPVs counts PVs with 'm' (missing) flag in pv_attr and updates VG counts.
// pv_attr[2] == 'm' means the PV is missing from the system.
func mergeMissingPVs(out string, vgs []models.LVMVG) {
	missing := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		vgName := fields[0]
		attr := fields[1]
		// pv_attr is a string like "a--" — char 2 is 'm' if missing
		if len(attr) > 2 && attr[2] == 'm' {
			missing[vgName]++
		}
	}
	for i, vg := range vgs {
		if n, ok := missing[vg.Name]; ok {
			vgs[i].MissingPVs = n
		}
	}
}

// parseLVs parses `lvs` output and separates thin pools from snapshots.
// lv_attr[0] values: 't' = thin pool, 's' = snapshot, 'S' = merging snapshot
func parseLVs(out string) (thinPools []models.LVMThinPool, snapshots []models.LVMSnapshot) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		lvName := fields[0]
		vgName := fields[1]
		attr := fields[2]
		dataPct, _ := strconv.ParseFloat(fields[3], 64)
		metaPct, _ := strconv.ParseFloat(fields[4], 64)

		if len(attr) == 0 {
			continue
		}

		switch attr[0] {
		case 't': // thin pool
			sizeGB := 0.0
			if len(fields) >= 7 {
				sizeGB, _ = strconv.ParseFloat(fields[6], 64)
			}
			thinPools = append(thinPools, models.LVMThinPool{
				Name:    lvName,
				VG:      vgName,
				DataPct: dataPct,
				MetaPct: metaPct,
				SizeGB:  sizeGB,
			})
		case 's', 'S': // snapshot or merging snapshot
			origin := ""
			if len(fields) >= 6 {
				origin = fields[5]
			}
			snapshots = append(snapshots, models.LVMSnapshot{
				Name:    lvName,
				VG:      vgName,
				Origin:  origin,
				DataPct: dataPct,
			})
		}
	}
	return thinPools, snapshots
}
