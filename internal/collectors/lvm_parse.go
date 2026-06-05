// lvm_parse.go — pure string parsers for LVM command output.
// No build tag: these functions have zero Linux syscall dependencies
// and can be tested on any platform (macOS, Linux, CI).
// The Linux-only collector (lvm_linux.go) calls these after running
// vgs / pvs / lvs via exec.

package collectors

import (
	"strconv"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// parseLVMFloat parses an LVM size field. LVM prefixes rounded/approximate values
// with "<" (or ">") even under --nosuffix --units g (e.g. "<5.00" = "a little under
// 5 GiB"); a plain ParseFloat on that returns 0, which would read as zero free space
// and trigger a false "volume full" alert. Strip the marker before parsing.
func parseLVMFloat(s string) float64 {
	s = strings.TrimLeft(strings.TrimSpace(s), "<>")
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// parseVGs parses `vgs --noheadings --nosuffix --units g -o vg_name,vg_size,vg_free,vg_attr` output.
func parseVGs(out string) []models.LVMVG {
	var vgs []models.LVMVG
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		vg := models.LVMVG{Name: fields[0]}
		vg.SizeGB = parseLVMFloat(fields[1])
		vg.FreeGB = parseLVMFloat(fields[2])
		if vg.SizeGB > 0 {
			vg.FreePct = vg.FreeGB / vg.SizeGB * 100
		}
		vgs = append(vgs, vg)
	}
	return vgs
}

// mergeMissingPVs counts PVs with the 'm' (missing) flag in pv_attr and
// updates VG counts. pv_attr[2] == 'm' means the PV is missing from the system.
// Input: `pvs --noheadings -o vg_name,pv_attr` output.
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

// parseLVs parses `lvs --noheadings --nosuffix --units g
// -o lv_name,vg_name,lv_attr,data_percent,metadata_percent,origin,lv_size` output.
// lv_attr[0] values: 't' = thin pool, 's' = snapshot, 'S' = merging snapshot.
func parseLVs(out string) (thinPools []models.LVMThinPool, snapshots []models.LVMSnapshot) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		lvName := fields[0]
		vgName := fields[1]
		attr := fields[2]
		dataPct := parseLVMFloat(fields[3])
		metaPct := parseLVMFloat(fields[4])

		if len(attr) == 0 {
			continue
		}

		switch attr[0] {
		case 't': // thin pool — no origin column, so fields are:
			// [name, vg, attr, data%, meta%, size_gb]  (6 fields)
			sizeGB := 0.0
			if len(fields) >= 6 {
				sizeGB = parseLVMFloat(fields[5])
			}
			thinPools = append(thinPools, models.LVMThinPool{
				Name:    lvName,
				VG:      vgName,
				DataPct: dataPct,
				MetaPct: metaPct,
				SizeGB:  sizeGB,
			})
		case 's', 'S': // classic snapshot (copy-on-write, origin is a regular LV)
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
		case 'V': // thin volume — may be a thin snapshot if it has an origin (attr[9]=='k')
			// lv_attr is 10 chars: VolumeType, Permissions, Allocation, Fixed, State,
			// DeviceOpen, TargetType, ZeroNew, VolumeHealth, SkipActivation
			// attr[9]='k' means "skip activation" — for thin LVs this indicates a thin snapshot.
			//
			// IMPORTANT: when data_percent is empty (thin snapshot of thin LV may show blank),
			// lvs outputs blank columns which collapse under strings.Fields. To find the origin
			// reliably, we look for a non-numeric field after lv_name,vg_name,lv_attr —
			// the origin is always the last string field before lv_size (the final float).
			if len(attr) > 9 && attr[9] == 'k' {
				origin := findLVOrigin(fields)
				snapshots = append(snapshots, models.LVMSnapshot{
					Name:    lvName,
					VG:      vgName,
					Origin:  origin,
					DataPct: dataPct,
				})
			}
		}
	}
	return thinPools, snapshots
}

// findLVOrigin extracts the origin LV name from a parsed lvs field slice.
// The origin is a non-numeric string field that appears after the first 3
// mandatory fields (lv_name, vg_name, lv_attr). The last field is always
// lv_size (a float), so the origin must appear before it.
//
// This handles the case where data_percent and metadata_percent are blank
// (e.g. thin snapshots of thin LVs) — lvs outputs spaces which collapse
// under strings.Fields, shifting field positions unpredictably.
func findLVOrigin(fields []string) string {
	if len(fields) < 4 {
		return ""
	}
	// Work backwards from the second-to-last field.
	// Last field is lv_size (numeric). Look for the first non-numeric
	// field scanning backwards, skipping the last field.
	for i := len(fields) - 2; i >= 3; i-- {
		f := fields[i]
		if _, err := strconv.ParseFloat(f, 64); err != nil {
			// Not a number — this is the origin LV name
			return f
		}
	}
	return ""
}
