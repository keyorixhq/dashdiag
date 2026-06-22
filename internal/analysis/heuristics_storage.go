package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// nvmeSmartPlausible reports whether an NVMe SMART reading is physically
// possible. Some virtual NVMe devices (notably VMware Cloud Director's vNVMe,
// TRIAGE §L) return a SMART log that parses cleanly but is garbage — e.g.
// temperature 11758°C, available_spare 1% against threshold 100%, counters at
// ~2^63–2^64 (uninitialised/sentinel fields). The read SUCCEEDS, so SmartRead
// is true and the values are non-zero, which means the spare<=threshold
// "near end of life" gate and the temp gate both fire on data whose own sibling
// fields are impossible — a false CRIT on a healthy virtual drive.
//
// This is the implausible-value sibling of the SmartRead guard: SmartRead
// catches "never measured", this catches "measured garbage". When it returns
// false the caller must treat the device as health-unverified (route to the
// "detected but not verified" INFO path), NOT score its fields.
// nvmeTempSentinel reports whether the temperature reading is the 0-Kelvin
// "not reported" sentinel (-273°C). Virtual/cloud NVMe (AWS EBS, and other
// hypervisor-presented volumes) expose no temperature sensor and return 0 K,
// which the tool prints as "-273 °C". This is "unreported", NOT garbage — it must
// be distinguished from a device actively reporting an impossible temperature
// (VMware's 11758°C), which IS garbage and stays rejected.
func nvmeTempSentinel(dev models.NVMeDevice) bool {
	return dev.TempC <= -273
}

// NVMeNoRealData reports whether the SMART log was read but every field is at its
// not-reported sentinel — a virtual/cloud volume (e.g. AWS EBS) that passes no
// real SMART telemetry. The 0-Kelvin temp is the tell; a real drive reports a
// real temperature. Exported so the renderer's inline summary agrees with the
// heuristic (a no-data drive must not render "healthy"). Distinct from "implausible"
// (active garbage → WARN) and from "unread" (no nvme-cli → INFO).
func NVMeNoRealData(dev models.NVMeDevice) bool {
	return nvmeTempSentinel(dev) &&
		dev.AvailableSparePct == 0 && dev.SpareThresholdPct == 0 &&
		dev.PercentageUsed == 0 && dev.CriticalWarning == 0 &&
		dev.MediaErrors == 0 && dev.UnsafeShutdowns == 0 &&
		dev.PowerOnHours == 0 && dev.PowerCycles == 0
}

func nvmeSmartPlausible(dev models.NVMeDevice) bool {
	// Temperature: NVMe operating/storage range is generously [-40, 125]°C. The
	// 0-Kelvin sentinel (-273) is "not reported", not garbage (see nvmeTempSentinel)
	// — exempt it so a virtual/cloud volume isn't rejected as implausible.
	if !nvmeTempSentinel(dev) && (dev.TempC < -40 || dev.TempC > 125) {
		return false
	}
	// Percentages are 0–100 by spec (PercentageUsed may report >100 on
	// genuinely worn drives, so only gate the spare/threshold pair, which is
	// strictly bounded).
	if dev.AvailableSparePct < 0 || dev.AvailableSparePct > 100 {
		return false
	}
	if dev.SpareThresholdPct < 0 || dev.SpareThresholdPct > 100 {
		return false
	}
	// Counters: a real drive has not been powered for 10^9+ hours nor cycled
	// 10^9+ times. These sit near 2^63 on the garbage path; a sane ceiling of
	// ~114 years of hours / a billion cycles rejects sentinels without touching
	// any real enterprise drive.
	const maxPlausibleHours = 1_000_000 // ~114 years
	const maxPlausibleCycles = 1_000_000_000
	if dev.PowerOnHours < 0 || dev.PowerOnHours > maxPlausibleHours {
		return false
	}
	if dev.PowerCycles < 0 || dev.PowerCycles > maxPlausibleCycles {
		return false
	}
	return true
}

// sataSmartPlausible is the SATA/SAS sibling of nvmeSmartPlausible (TRIAGE §L,
// §E.3 sibling-divergence). The SATA scoring path reads its error counters from
// raw ATA SMART attribute values (id 5/197/198), and those raw fields are
// notoriously vendor-encoded — some drives pack temperature, timestamps, or
// other data into the raw column, so a non-zero "uncorrectable" raw can be a
// false-CRIT source on perfectly healthy consumer drives, not only on virtual
// SATA controllers (VMware/QEMU) and USB-SATA bridges that emit sentinel
// garbage. When this returns false the caller must route the device to the
// "detected but health-unverified" WARN path and NOT score its attribute fields,
// exactly as the NVMe path does. The drive's own smart_status verdict is also
// considered untrustworthy here — a device reporting physically-impossible
// attributes is not a reliable narrator of its own pass/fail.
func sataSmartPlausible(dev models.SATADevice) bool {
	// Temperature: SATA HDD/SSD operating + storage range is generously
	// [-40, 125]°C; the garbage path reports thousands of degrees.
	if dev.TempC < -40 || dev.TempC > 125 {
		return false
	}
	// Sector counters are bounded by the drive's sector count, and a drive with
	// even ~10^5 reallocated/pending/uncorrectable sectors is long dead and would
	// already fail its SMART self-assessment. A ceiling of 10^8 rejects sentinel
	// values (raw fields sitting near 2^31/2^63, or a packed vendor encoding read
	// as a plain count) without suppressing any real failing drive. Negative is
	// impossible for a count (raw int64→int wrap on garbage).
	const maxPlausibleSectors = 100_000_000
	if dev.ReallocatedSectors < 0 || dev.ReallocatedSectors > maxPlausibleSectors {
		return false
	}
	if dev.PendingSectors < 0 || dev.PendingSectors > maxPlausibleSectors {
		return false
	}
	if dev.UncorrectableErrors < 0 || dev.UncorrectableErrors > maxPlausibleSectors {
		return false
	}
	// Power-on hours: same ~114-year ceiling as NVMe (id 9 raw is also vendor-
	// encoded on some drives and can read as a sentinel).
	const maxPlausibleHours = 1_000_000
	if dev.PowerOnHours < 0 || dev.PowerOnHours > maxPlausibleHours {
		return false
	}
	return true
}

func checkNVMe(n models.NVMeInfo) []models.Insight { //nolint:funlen,cyclop // NVMe + SATA/SAS checks — flat registry of independent per-drive checks
	var out []models.Insight

	// NVMe drives
	var implausible, noData []string
	for _, dev := range n.Devices {
		// Guard against implausible (garbage-but-parseable) SMART logs before
		// any scoring — see nvmeSmartPlausible / TRIAGE §L. A device whose
		// SMART was read but is physically impossible must not score its fields
		// (the spare<=threshold gate below would false-CRIT on it); route it to
		// the health-unverified path instead, exactly like an unread drive.
		if dev.SmartRead && !nvmeSmartPlausible(dev) {
			implausible = append(implausible, dev.Name)
			continue
		}
		// SMART read but all fields are not-reported sentinels (0-Kelvin temp +
		// all-zero) — a virtual/cloud volume (e.g. AWS EBS) that exposes no real
		// telemetry. Surface as INFO "no real SMART data", NOT a confident
		// "healthy" (false-OK) and NOT the implausible-garbage WARN (which fired
		// fleet-wide on every EBS volume before this gate). See NVMeNoRealData.
		if dev.SmartRead && NVMeNoRealData(dev) {
			noData = append(noData, dev.Name)
			continue
		}
		if dev.CriticalWarning > 0 {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s critical warning flag set (0x%02x) — drive may be failing", dev.Name, dev.CriticalWarning),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.MediaErrors > 0 {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s has %d media error(s) — data integrity risk", dev.Name, dev.MediaErrors),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		// Gate on the threshold (a defined NVMe SMART field, ~10% on healthy
		// drives) rather than on AvailableSparePct itself: AvailableSparePct==0
		// is the WORST reading (spare fully exhausted), but the old `> 0` guard
		// silently dropped it. SpareThresholdPct>0 means the SMART log was read,
		// so spare<=threshold (including 0) is a real CRIT; both-zero (unread)
		// still stays silent.
		if dev.SpareThresholdPct > 0 && dev.AvailableSparePct <= dev.SpareThresholdPct {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s spare capacity at %d%% (threshold: %d%%) — drive near end of life", dev.Name, dev.AvailableSparePct, dev.SpareThresholdPct),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		} else if dev.AvailableSparePct > 0 && dev.AvailableSparePct < 20 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s spare capacity low at %d%%", dev.Name, dev.AvailableSparePct),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.PercentageUsed >= 90 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s wear at %d%% — consider replacement planning", dev.Name, dev.PercentageUsed),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.TempC >= 70 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s temperature %g°C — elevated for NVMe", dev.Name, dev.TempC),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.UnsafeShutdowns > 100 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d unsafe shutdown(s) — power cuts risk filesystem corruption", dev.Name, dev.UnsafeShutdowns),
				[]string{"to inspect: nvme smart-log " + dev.Name, "to inspect: nvme list", "to fix: ensure clean shutdowns, check UPS"},
			))
		}
		if dev.PowerOnHours > 35000 {
			// Power-on hours is age, not wear — a long-lived enterprise/healthy drive
			// is fine. Real endurance is PercentageUsed / AvailableSpare (checked above),
			// so this is INFO context, not a WARN.
			out = append(out, insight("INFO", "Drives",
				fmt.Sprintf("%s has %d power-on hours (~%.1f years) — age only; wear is tracked via percentage-used/spare, not hours", dev.Name, dev.PowerOnHours, float64(dev.PowerOnHours)/8760),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
	}

	// NVMe drives detected via sysfs but with no SMART log read (nvme-cli absent,
	// common on minimal cloud/ARM images). Surface this rather than letting the
	// drive default to a confident "healthy" — health was never verified.
	var unread []string
	for _, dev := range n.Devices {
		if !dev.SmartRead {
			unread = append(unread, dev.Name)
		}
	}
	if len(unread) > 0 {
		out = append(out, insight("INFO", "Drives",
			fmt.Sprintf("%d NVMe drive(s) detected but SMART health not read (%s) — nvme-cli not installed",
				len(unread), strings.Join(unread, ", ")),
			[]string{
				"to fix: install nvme-cli  (apt install nvme-cli  /  dnf install nvme-cli)",
				"note: drive presence is known; wear, media errors, and spare capacity are unverified",
			},
		))
	}

	// NVMe drives whose SMART log was read but is physically implausible
	// (TRIAGE §L — VMware vNVMe returns garbage-but-parseable fields). Health is
	// unverified, same as an unread drive, but surface it distinctly: the data
	// is actively wrong, not merely absent, and a consumer should know the
	// device reported nonsense rather than assume a missing tool.
	if len(implausible) > 0 {
		out = append(out, insight("WARN", "Drives",
			fmt.Sprintf("%d NVMe drive(s) returned implausible SMART data (%s) — health unverified, values rejected",
				len(implausible), strings.Join(implausible, ", ")),
			[]string{
				"to inspect: nvme smart-log " + implausible[0],
				"note: out-of-range temperature/spare/counters (common on virtual NVMe, e.g. VMware) — readings ignored to avoid a false end-of-life alarm",
			},
		))
	}

	// NVMe drives whose SMART read returned only not-reported sentinels (0-Kelvin
	// temp + all-zero) — virtual/cloud volumes (e.g. AWS EBS) that pass no real
	// SMART. INFO, not a confident "healthy" (nothing was measured) and not the
	// implausible-garbage WARN (for a device actively lying, e.g. VMware's 11758°C).
	// High blast radius: pre-gate, every EBS volume on every EC2 instance tripped
	// the implausible WARN.
	if len(noData) > 0 {
		out = append(out, insight("INFO", "Drives",
			fmt.Sprintf("%d NVMe drive(s) expose no real SMART telemetry (%s) — virtual/cloud volume (e.g. AWS EBS); temperature/wear/spare not reported, on-device health not measurable",
				len(noData), strings.Join(noData, ", ")),
			[]string{
				"note: virtual block devices don't pass through real SMART — drive presence is known, but wear/spare/temperature are not measurable",
			},
		))
	}

	// SATA/SAS drives
	var sataUnread, sataImplausible []string
	for _, dev := range n.SATADevices {
		// smartctl could not read this drive's SMART — it errored (permission /
		// non-root, transient) or returned no smart_status (USB bridge, RAID/HBA
		// member, virtual disk). Either way health is UNVERIFIED → surface it (INFO),
		// do NOT silently skip: a silent skip let the inline summary count the drive
		// as healthy, a non-root false-OK validated on pve01 (smartctl needs root, so
		// an unprivileged `dsd health` read "2 drives healthy" while SMART was never
		// read). Never a confident "drive may be failing" CRIT on an unverified drive.
		if dev.Error != "" || !dev.SmartRead {
			sataUnread = append(sataUnread, dev.Name)
			continue
		}
		// Read succeeded but the values are physically impossible (garbage raw ATA
		// attributes — vendor-encoded raw fields, virtual SATA controllers, USB
		// bridges; see sataSmartPlausible / TRIAGE §L §E.3). Route to the
		// implausible WARN and DO NOT score any field — including the smart_status
		// verdict, which is untrustworthy on a drive reporting impossible attrs.
		if !sataSmartPlausible(dev) {
			sataImplausible = append(sataImplausible, dev.Name)
			continue
		}
		if !dev.SmartOK {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s (%s) SMART check FAILED — drive may be failing", dev.Name, dev.Type),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.ReallocatedSectors > 0 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d reallocated sector(s) — early sign of drive failure", dev.Name, dev.ReallocatedSectors),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.PendingSectors > 0 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d pending sector(s) — unreadable sectors awaiting reallocation", dev.Name, dev.PendingSectors),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.UncorrectableErrors > 0 {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s has %d uncorrectable error(s) — data loss risk", dev.Name, dev.UncorrectableErrors),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.TempC >= 55 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s (%s) temperature %d°C — elevated for SATA drive", dev.Name, dev.Type, dev.TempC),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.PowerOnHours > 43800 {
			// Age, not health — enterprise/NAS HDDs routinely run 5+ years 24/7.
			// On its own this is not a failure signal; reallocated/pending sectors
			// and a failing SMART self-assessment (checked above) are. INFO context.
			out = append(out, insight("INFO", "Drives",
				fmt.Sprintf("%s (%s) has %d power-on hours (~%.1f years) — age only; not a failure signal on its own (check reallocated/pending sectors)", dev.Name, dev.Type, dev.PowerOnHours, float64(dev.PowerOnHours)/8760),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
	}
	if len(sataImplausible) > 0 {
		out = append(out, insight("WARN", "Drives",
			fmt.Sprintf("%d SATA/SAS drive(s) returned implausible SMART data (%s) — health unverified, values rejected",
				len(sataImplausible), strings.Join(sataImplausible, ", ")),
			[]string{
				"to inspect: smartctl -a " + sataImplausible[0],
				"note: out-of-range temperature/sector-counts (vendor-encoded raw attributes, or virtual/USB-bridged SATA) — readings ignored to avoid a false drive-failure alarm",
			},
		))
	}
	if len(sataUnread) > 0 {
		out = append(out, insight("INFO", "Drives",
			fmt.Sprintf("%d SATA/SAS drive(s) detected but SMART health not read (%s) — running unprivileged (smartctl needs root), or a drive behind a RAID/HBA controller or USB bridge that doesn't pass SMART, or a virtual disk",
				len(sataUnread), strings.Join(sataUnread, ", ")),
			[]string{
				"to fix: re-run as root — SMART reads require privilege (sudo dsd health)",
				"to inspect: smartctl -a <device>  (try -d sat / -d cciss,N for controllers)",
				"note: drive presence is known; SMART health, wear, and errors are unverified",
			},
		))
	}

	return out
}

// checkZFS surfaces ZFS pool health issues: degraded state, capacity, errors, scrub age.
// ZFS is used heavily by Proxmox, TrueNAS-derived systems, and enterprise Linux.
// zfsVdevErrorLevel classifies a pool's cumulative R/W/Cksum vdev counters. Those
// counters tally every error since the last `zpool clear` — INCLUDING ones ZFS
// already repaired from redundancy — and persist until cleared, so a transient or
// repaired blip on a healthy pool would otherwise read as a permanent CRIT. Real,
// current corruption is signalled separately (a non-ONLINE State, or unrepairable
// ScrubErrors), and stays CRIT here too; an ONLINE pool whose last scrub was clean
// is WARN (investigate/clear), since the errors were repaired. "" = no errors.
func zfsVdevErrorLevel(p models.ZFSPool) string {
	if p.ReadErrors+p.WriteErrors+p.CksumErrors == 0 {
		return ""
	}
	if (p.State != "" && p.State != "ONLINE") || p.ScrubErrors > 0 {
		return "CRIT"
	}
	return "WARN"
}

// zfsVdevErrorInsight builds the insight for a pool's cumulative vdev error
// counters (or ok=false when there are none). Shared by the disk and ZFS checks
// so they assign the same severity for the same condition. check is the insight
// category label ("Disk" or "ZFS").
func zfsVdevErrorInsight(p models.ZFSPool, check string) (models.Insight, bool) {
	lvl := zfsVdevErrorLevel(p)
	if lvl == "" {
		return models.Insight{}, false
	}
	counts := fmt.Sprintf("R:%d W:%d C:%d", p.ReadErrors, p.WriteErrors, p.CksumErrors)
	if lvl == "WARN" {
		return insight("WARN", check,
			fmt.Sprintf("ZFS pool %s recorded vdev errors (%s) since last clear — repaired (pool ONLINE, last scrub clean); investigate if recurring", p.Name, counts),
			[]string{
				fmt.Sprintf("to inspect: zpool status -v %s", p.Name),
				"note: counters persist until cleared — recurring checksum errors can mean bad disk/RAM/cable",
				fmt.Sprintf("to clear after confirming healthy: zpool clear %s", p.Name),
			},
		), true
	}
	reason := fmt.Sprintf("pool is %s", p.State)
	if p.ScrubErrors > 0 {
		reason = fmt.Sprintf("last scrub left %d unrepairable error(s)", p.ScrubErrors)
	}
	return insight("CRIT", check,
		fmt.Sprintf("ZFS pool %s has vdev errors (%s) — %s", p.Name, counts, reason),
		[]string{
			fmt.Sprintf("to inspect: zpool status -v %s", p.Name),
			"note: checksum errors indicate data corruption or bad hardware",
			fmt.Sprintf("to clear after fixing root cause: zpool clear %s", p.Name),
		},
	), true
}

func checkZFS(z models.ZFSInfo) []models.Insight {
	out := make([]models.Insight, 0, len(z.Pools))
	if z.ListReadFailed {
		// zpool is installed but `zpool list` failed (commonly permission denied) —
		// no pool was inspected, so don't pass as a silent "no ZFS problems".
		out = append(out, insight("INFO", "ZFS",
			"ZFS is present but pools could NOT be verified — `zpool list` failed (run as root?)",
			[]string{"to inspect: zpool list", "to inspect: zpool status"}))
	}
	for _, pool := range z.Pools {
		out = append(out, checkZFSPool(pool)...)
	}
	return out
}

// checkZFSPool checks a single ZFS pool — extracted to keep funlen within linter limits.
func checkZFSPool(pool models.ZFSPool) []models.Insight { //nolint:funlen // flat list of independent pool checks
	var out []models.Insight

	// Pool state — anything other than ONLINE is a problem
	switch pool.State {
	case "DEGRADED":
		msg := fmt.Sprintf("ZFS pool %s is DEGRADED", pool.Name)
		if pool.StatusMsg != "" {
			msg += " — " + pool.StatusMsg
		}
		out = append(out, insight("CRIT", "ZFS", msg,
			[]string{
				fmt.Sprintf("to inspect: zpool status %s", pool.Name),
				fmt.Sprintf("to inspect: zpool events %s", pool.Name),
				"note: replace failed vdev and run: zpool replace <pool> <old> <new>",
				"note: data is at risk — restore redundancy immediately",
			},
		))
	case "FAULTED":
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s is FAULTED — pool may be unrecoverable", pool.Name),
			[]string{
				fmt.Sprintf("to inspect: zpool status -v %s", pool.Name),
				"note: FAULTED means pool was taken offline due to unrecoverable error",
				"note: import with: zpool import -F <pool>  (force recovery, may lose data)",
			},
		))
	case "REMOVED", "UNAVAIL", "OFFLINE":
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s state: %s", pool.Name, pool.State),
			[]string{
				fmt.Sprintf("to inspect: zpool status -v %s", pool.Name),
				fmt.Sprintf("to inspect: zpool events %s", pool.Name),
			},
		))
	}

	// Capacity — ZFS copy-on-write degrades badly above 80%, writes fail above 90%
	if l := levelPct(pool.UsedPct, DefaultDiskWarnPct, DefaultDiskCritPct); l != "" {
		out = append(out, insight(l, "ZFS",
			fmt.Sprintf("ZFS pool %s is %.0f%% full (%.1f GB free of %.1f GB)",
				pool.Name, pool.UsedPct, pool.FreeGB, pool.SizeGB),
			[]string{
				fmt.Sprintf("to inspect: zfs list -r %s", pool.Name),
				"note: ZFS performance degrades significantly above 80% capacity",
				"note: above 90%, writes may fail — free space or expand pool",
				"to free space: zfs destroy <snapshot>  (remove old snapshots)",
			},
		))
	}

	// Fragmentation
	if pool.FragPct >= 70 {
		out = append(out, insight("WARN", "ZFS",
			fmt.Sprintf("ZFS pool %s fragmentation at %d%% — read/write amplification likely", pool.Name, pool.FragPct),
			[]string{
				fmt.Sprintf("to inspect: zpool list %s", pool.Name),
				"note: fragmentation above 70% causes significant performance degradation",
			},
		))
	} else if pool.FragPct >= 50 {
		out = append(out, insight("INFO", "ZFS",
			fmt.Sprintf("ZFS pool %s fragmentation at %d%%", pool.Name, pool.FragPct),
			[]string{fmt.Sprintf("to inspect: zpool list %s", pool.Name)},
		))
	}

	// Cumulative vdev error counters — severity gated on actual pool health so a
	// repaired/transient error on an ONLINE pool isn't a perpetual CRIT.
	if ins, ok := zfsVdevErrorInsight(pool, "ZFS"); ok {
		out = append(out, ins)
	}

	// Errors found by the LAST scrub (the "with N errors" in zpool status) — data
	// errors the scrub could not repair, i.e. permanent corruption of specific
	// files. Distinct from the cumulative vdev counters above (which include
	// repaired errors), and was parsed by the collector but never surfaced.
	if pool.ScrubErrors > 0 {
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s: last scrub found %d unrepairable error(s) — permanent data corruption", pool.Name, pool.ScrubErrors),
			[]string{
				fmt.Sprintf("to inspect: zpool status -v %s", pool.Name),
				"note: 'zpool status -v' lists the affected files — restore them from backup",
			},
		))
	}

	// `zpool status` couldn't be read (it can hang/timeout on a sick pool). The pool
	// State is still known from `zpool list`, but per-vdev error counts and scrub age
	// are not — so the error-count check above couldn't fire and ScrubAgeDays is -1
	// (NOT "never scrubbed"). On an otherwise-ONLINE pool, surface that it's
	// unverified rather than pass as clean; and skip the scrub-age check below.
	if pool.StatusReadFailed {
		if pool.State == "" || pool.State == "ONLINE" {
			out = append(out, insight("INFO", "ZFS",
				fmt.Sprintf("ZFS pool %s is ONLINE, but `zpool status` could not be read — per-vdev error counts and scrub status are unverified", pool.Name),
				[]string{fmt.Sprintf("to inspect: zpool status %s  (it can hang on a sick pool — check dmesg)", pool.Name)}))
		}
		return out
	}

	// Scrub age — periodic scrubs detect silent corruption
	switch {
	case pool.ScrubAgeDays < 0:
		out = append(out, insight("WARN", "ZFS",
			fmt.Sprintf("ZFS pool %s has never been scrubbed — silent corruption risk", pool.Name),
			[]string{
				fmt.Sprintf("to run scrub: zpool scrub %s", pool.Name),
				"note: monthly scrubs are recommended for all ZFS pools",
				"to automate: systemctl enable zfs-scrub.timer  (if available)",
			},
		))
	case pool.ScrubAgeDays > 30:
		out = append(out, insight("INFO", "ZFS",
			fmt.Sprintf("ZFS pool %s last scrubbed %d days ago (recommended: monthly)", pool.Name, pool.ScrubAgeDays),
			[]string{fmt.Sprintf("to run scrub: zpool scrub %s", pool.Name)},
		))
	}

	return out
}

// checkLVM surfaces LVM health issues: thin pool exhaustion, VG free space,
// snapshot overflow, and missing PVs. Thin pool exhaustion is the #1 silent
// failure in Proxmox/KVM environments — VMs freeze with no warning.
func checkLVM(l models.LVMInfo) []models.Insight {
	var out []models.Insight

	// Thin pool data and metadata usage — CRIT thresholds are tight because
	// exhaustion happens fast and recovery requires unmounting everything.
	for _, pool := range l.ThinPools {
		// Data exhaustion: 80% WARN, 90% CRIT (see analysis/thresholds.go)
		if lv := LVMThinPoolLevel(pool.DataPct); lv != "" {
			out = append(out, insight(lv, "LVM",
				fmt.Sprintf("thin pool %s/%s data at %.0f%% (%.1f GB total)",
					pool.VG, pool.Name, pool.DataPct, pool.SizeGB),
				[]string{
					fmt.Sprintf("to inspect: lvs %s/%s", pool.VG, pool.Name),
					fmt.Sprintf("to extend:  lvextend -l +50%%FREE %s/%s", pool.VG, pool.Name),
					"note: thin pool exhaustion silently freezes all VMs writing to it",
					"note: set lvm.conf thin_pool_autoextend_threshold=80 to auto-extend",
				},
			))
		}
		// Metadata exhaustion: 50% WARN, 75% CRIT (much more dangerous than data)
		// Metadata exhaustion cannot be easily recovered and requires pool deactivation.
		if lv := levelPct(pool.MetaPct, 50, 75); lv != "" {
			out = append(out, insight(lv, "LVM",
				fmt.Sprintf("thin pool %s/%s metadata at %.0f%% — metadata exhaustion is unrecoverable without deactivation",
					pool.VG, pool.Name, pool.MetaPct),
				[]string{
					fmt.Sprintf("to inspect: lvs %s/%s", pool.VG, pool.Name),
					fmt.Sprintf("to extend:  lvextend --poolmetadatasize +1G %s/%s", pool.VG, pool.Name),
					"note: metadata exhaustion is worse than data exhaustion — act immediately",
				},
			))
		}
	}

	// A VG that backs a thin pool is, by design, almost fully *allocated* to that
	// pool — Proxmox's default layout hands nearly the whole VG to the `data` thin
	// pool. "VG ~98% allocated" is then the normal healthy state, not a near-full
	// disk: the number that matters is the thin pool's own data/metadata fill,
	// scored above. Scoring VG free here produces a false near-full CRIT on every
	// Proxmox host (and any thin-provisioned VG). Skip the VG-fullness check for
	// thin-pool-backed VGs; MissingPVs (a real risk regardless) is still scored. (§O.1)

	// VG free space — skip inactive VGs (no mounted LVs = leftover OS partition)
	for _, vg := range l.VGs {
		if !vg.HasMountedLV {
			out = append(out, insight("INFO", "LVM",
				fmt.Sprintf("inactive volume group %s is %.0f%% full — no LVs mounted (old OS partition?)",
					vg.Name, 100-vg.FreePct),
				[]string{
					fmt.Sprintf("to inspect: vgs %s", vg.Name),
					fmt.Sprintf("to inspect: lvs | grep %s", vg.Name),
					"note: this VG has no mounted LVs on this OS — likely a leftover from a previous install",
				},
			))
			continue
		}
		if lv := LVMVGFullLevel(vg.FreePct); lv != "" && !VGBacksThinPool(l.ThinPools, vg.Name) {
			out = append(out, insight(lv, "LVM",
				fmt.Sprintf("volume group %s is %.0f%% full (%.1f GB free of %.1f GB)",
					vg.Name, 100-vg.FreePct, vg.FreeGB, vg.SizeGB),
				[]string{
					fmt.Sprintf("to inspect: vgs %s", vg.Name),
					fmt.Sprintf("to inspect: pvs | grep %s", vg.Name),
					"to add PV:  pvcreate /dev/<new-disk> && vgextend <vg> /dev/<new-disk>",
				},
			))
		}
		// Missing PVs — a PV has been removed or failed
		if vg.MissingPVs > 0 {
			out = append(out, insight("CRIT", "LVM",
				fmt.Sprintf("volume group %s has %d missing PV(s) — data at risk",
					vg.Name, vg.MissingPVs),
				[]string{
					fmt.Sprintf("to inspect: pvs | grep %s", vg.Name),
					fmt.Sprintf("to inspect: vgreduce --removemissing %s  (removes missing PVs)", vg.Name),
					"note: missing PVs mean LVs on that device are inaccessible",
				},
			))
		}
	}

	// Snapshots — COW table overflow corrupts the snapshot
	for _, snap := range l.Snapshots {
		if lv := LVMSnapshotLevel(snap.DataPct); lv != "" {
			out = append(out, insight(lv, "LVM",
				fmt.Sprintf("snapshot %s/%s is %.0f%% full — overflow will corrupt the snapshot",
					snap.VG, snap.Name, snap.DataPct),
				[]string{
					fmt.Sprintf("to inspect: lvs %s/%s", snap.VG, snap.Name),
					fmt.Sprintf("to extend:  lvextend -L +1G %s/%s", snap.VG, snap.Name),
					fmt.Sprintf("to remove:  lvremove %s/%s  (if snapshot is no longer needed)", snap.VG, snap.Name),
				},
			))
		}
	}

	out = append(out, checkLVMRaid(l)...)
	return out
}

func checkLVMRaid(l models.LVMInfo) []models.Insight {
	var out []models.Insight
	// RAID/mirror LV health
	for _, r := range l.RaidLVs {
		if r.Degraded {
			out = append(out, insight("CRIT", "LVM",
				fmt.Sprintf("%s LV %s/%s is DEGRADED — one or more PVs failed", r.Type, r.VG, r.Name),
				[]string{
					fmt.Sprintf("to inspect: lvs -a -o name,vg_name,lv_attr,devices %s/%s", r.VG, r.Name),
					"to inspect: pvs  (identify failed PV)",
					"to recover: lvconvert --repair " + r.VG + "/" + r.Name,
				},
			))
		} else if r.Resyncing {
			out = append(out, insight("INFO", "LVM",
				fmt.Sprintf("%s LV %s/%s is resyncing (%.1f%% complete) — degraded protection until complete",
					r.Type, r.VG, r.Name, r.SyncPct),
				[]string{
					fmt.Sprintf("to watch:  lvs -a %s/%s  (monitor sync%%)", r.VG, r.Name),
					"note: do not remove any PV while resync is in progress",
				},
			))
		}
	}

	// RAID-LV health comes from a separate `lvs` query that can fail after the VG/LV
	// collection succeeded; without it a DEGRADED RAID LV is missed entirely. Only
	// flag when LVM is actually present (VGs found) so non-LVM hosts stay silent.
	if len(l.VGs) > 0 && l.RaidReadFailed {
		out = append(out, insight("INFO", "LVM",
			"LVM RAID/mirror LV health could not be read — a degraded RAID LV cannot be ruled out",
			[]string{"to inspect: lvs -o lv_name,vg_name,lv_attr,copy_percent"}))
	}

	// Each of vgs/pvs/lvs runs independently; a runtime failure (metadata lock
	// timeout, permission, transient device-mapper error) leaves the corresponding
	// data empty, which would read as a silent OK. The flags are only set on a host
	// where LVM IS installed (collector gate), so they imply presence on their own.
	if l.PVReadFailed {
		// Most dangerous: a failed `pvs` leaves MissingPVs=0, hiding a failed/removed PV.
		out = append(out, insight("INFO", "LVM",
			"LVM physical-volume state could NOT be verified — `pvs` failed; a missing/failed PV cannot be ruled out",
			[]string{"to inspect: pvs -o vg_name,pv_name,pv_attr", "note: run as root if permission denied"}))
	}
	if l.VGReadFailed {
		out = append(out, insight("INFO", "LVM",
			"LVM volume-group state could NOT be verified — `vgs` failed; VG free space not checked",
			[]string{"to inspect: vgs -o vg_name,vg_size,vg_free,vg_attr"}))
	}
	if l.LVReadFailed {
		out = append(out, insight("INFO", "LVM",
			"LVM logical-volume state could NOT be verified — `lvs` failed; thin-pool/snapshot usage not checked",
			[]string{"to inspect: lvs -o lv_name,vg_name,lv_attr,data_percent,metadata_percent"}))
	}

	return out
}

// checkDRBD surfaces DRBD replication issues: disconnection, split brain,
// disk state degradation, and sync progress. DRBD is used in Pacemaker/
// Corosync clusters — a split brain or disconnection means the HA layer
// is no longer protecting against node failure.
func checkDRBD(d models.DRBDInfo) []models.Insight {
	out := make([]models.Insight, 0, len(d.Resources))
	for _, res := range d.Resources {
		out = append(out, checkDRBDResource(res)...)
	}
	return out
}

// checkDRBDResource checks a single DRBD resource.
func checkDRBDResource(res models.DRBDResource) []models.Insight { //nolint:funlen // flat list of independent DRBD state checks
	var out []models.Insight
	name := fmt.Sprintf("drbd%d", res.Minor)

	// Connection state — the most critical signal
	switch res.ConnState {
	case "SplitBrain":
		// Split-brain: both nodes diverged and have different data.
		// This requires manual resolution — data loss is possible.
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: SPLIT-BRAIN detected — both nodes have diverged, manual resolution required", name),
			[]string{
				"note: split-brain means both nodes accepted conflicting writes",
				"to resolve (discard secondary): drbdadm secondary <resource>",
				"to resolve (discard secondary): drbdadm disconnect <resource>",
				"to resolve (discard secondary): drbdadm -- --discard-my-data connect <resource>",
				"to resolve (on primary):         drbdadm connect <resource>",
				"warning: always decide which node has authoritative data first",
			},
		))
	case "StandAlone":
		// StandAlone: not connected to peer, operating without replication.
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: STANDALONE — not connected to peer, no replication active", name),
			[]string{
				"to inspect: cat /proc/drbd",
				fmt.Sprintf("to reconnect: drbdadm connect %s", name),
				"note: data is not being replicated — single point of failure",
			},
		))
	case "WFConnection":
		// Waiting for connection — peer may be down or network issue
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: waiting for peer connection (WFConnection) — peer may be down", name),
			[]string{
				fmt.Sprintf("to inspect: drbdadm status %s", name),
				"to inspect: ping <peer-ip>",
				"to inspect: dmesg | grep -i drbd",
			},
		))
	case "Disconnecting":
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: disconnecting from peer", name),
			[]string{fmt.Sprintf("to inspect: drbdadm status %s", name)},
		))
	case "SyncSource", "SyncTarget":
		// Syncing — degraded but recoverable. Show progress.
		msg := fmt.Sprintf("%s: syncing (%.1f%% complete", name, res.SyncPct)
		if res.SyncKBLeft > 0 {
			msg += fmt.Sprintf(", %d MB remaining", res.SyncKBLeft/1024)
		}
		msg += ")"
		out = append(out, insight("INFO", "DRBD", msg,
			[]string{
				"to monitor: watch -n2 cat /proc/drbd",
				"note: do not restart the cluster until sync completes",
			},
		))
	}

	// Disk state — local disk health
	switch res.LocalDisk {
	case "Failed":
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: local disk state FAILED — underlying device has errors", name),
			[]string{
				fmt.Sprintf("to inspect: drbdadm status %s", name),
				"to inspect: dmesg | grep -E 'drbd|sda|sdb|nvme'",
				"to inspect: smartctl -a /dev/<underlying-device>",
			},
		))
	case "Detached":
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: local disk DETACHED — DRBD is not connected to underlying block device", name),
			[]string{
				fmt.Sprintf("to reattach: drbdadm attach %s", name),
				fmt.Sprintf("to inspect:  drbdadm status %s", name),
			},
		))
	case "Inconsistent":
		// Inconsistent during sync is normal — flag only if not syncing
		if res.ConnState != "SyncSource" && res.ConnState != "SyncTarget" {
			out = append(out, insight("CRIT", "DRBD",
				fmt.Sprintf("%s: local disk INCONSISTENT and not syncing", name),
				[]string{
					fmt.Sprintf("to inspect: drbdadm status %s", name),
					fmt.Sprintf("to force sync: drbdadm -- --overwrite-data-of-peer primary %s", name),
					"warning: only use --overwrite-data-of-peer if you are certain this node has correct data",
				},
			))
		}
	case "Outdated":
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: local disk OUTDATED — peer has newer data", name),
			[]string{
				fmt.Sprintf("to inspect: drbdadm status %s", name),
				"note: disk will sync automatically when peer connection is restored",
			},
		))
	}

	return out
}

// checkRAID surfaces degraded or failed mdadm RAID arrays from /proc/mdstat.
// A degraded array has lost redundancy — one more drive failure means data loss.
func checkRAID(r models.RAIDInfo) []models.Insight {
	var out []models.Insight
	for _, arr := range r.Arrays {
		switch arr.State {
		case "degraded":
			// A drive that's failed in place still shows as "(F)" in /proc/mdstat
			// (named in arr.Failed); a drive that's fully dropped out is gone from
			// the header — we know one is missing from the [n/m] counts but can't
			// name it. Only append the "failed: <names>" clause when we actually
			// have names, else the message renders a bare "failed: " (validated on
			// pve01, a removed-disk degraded array).
			detail := ""
			if len(arr.Failed) > 0 {
				detail = ", failed: " + strings.Join(arr.Failed, ", ")
			} else {
				detail = " — redundancy lost (a drive dropped out of the array)"
			}
			out = append(out, insight("CRIT", "RAID",
				fmt.Sprintf("%s (%s) is DEGRADED — %d/%d drives active%s",
					arr.Name, arr.Level, arr.Active, arr.Total, detail),
				[]string{
					"to inspect: cat /proc/mdstat",
					fmt.Sprintf("to inspect: mdadm --detail /dev/%s", arr.Name),
					"note: replace the failed drive and run: mdadm --add /dev/<array> /dev/<new-drive>",
					"note: data is at risk until redundancy is restored",
				},
			))
		case "recovering":
			out = append(out, insight("WARN", "RAID",
				fmt.Sprintf("%s (%s) is REBUILDING — %.1f%% complete",
					arr.Name, arr.Level, arr.RebuildPct),
				[]string{
					"to inspect: cat /proc/mdstat",
					"note: array is degraded during rebuild — avoid further drive failures",
					"note: rebuild progress updates every ~30s in /proc/mdstat",
				},
			))
		case "failed":
			out = append(out, insight("CRIT", "RAID",
				fmt.Sprintf("%s is FAILED — array is not operational", arr.Name),
				[]string{
					fmt.Sprintf("to inspect: mdadm --detail /dev/%s", arr.Name),
					"to inspect: dmesg | grep -i mdadm",
					"note: data may be lost — check individual drive health with smartctl",
				},
			))
		}
	}
	return out
}
