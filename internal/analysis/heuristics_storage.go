package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	inspectNVMEPrefix     = "to inspect: nvme smart-log "
	inspectSmartCtlPrefix = "to inspect: smartctl -a "
	inspectDRBDStatusFmt  = "to inspect: drbdadm status %s"
	inspectZPoolStatusFmt = "to inspect: zpool status -v %s"
	inspectZPoolEventsFmt = "to inspect: zpool events %s"
	inspectBtrfsStatsFmt  = "to inspect: btrfs device stats %s"
	inspectMultipath      = "to inspect: multipathd show paths"
	inspectLVSFmt         = "to inspect: lvs %s/%s"
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
// NVMeNoRealData reports whether the SMART log was read but every field is at its
// not-reported sentinel — a virtual/cloud volume (e.g. AWS EBS) that passes no
// real SMART telemetry. The 0-Kelvin temp (TempNotReported, see temp.go) is the
// tell; a real drive reports a real temperature. Exported so the renderer's inline
// summary agrees with the heuristic (a no-data drive must not render "healthy").
// Distinct from "implausible" (active garbage → WARN) and "unread" (no nvme-cli → INFO).
func NVMeNoRealData(dev models.NVMeDevice) bool {
	return TempNotReported(dev.TempC) &&
		dev.AvailableSparePct == 0 && dev.SpareThresholdPct == 0 &&
		dev.PercentageUsed == 0 && dev.CriticalWarning == 0 &&
		dev.MediaErrors == 0 && dev.UnsafeShutdowns == 0 &&
		dev.PowerOnHours == 0 && dev.PowerCycles == 0
}

func nvmeSmartPlausible(dev models.NVMeDevice) bool {
	// Temperature: NVMe operating/storage range. The 0-Kelvin sentinel (-273) is
	// "not reported", not garbage — exempt it so a virtual/cloud volume isn't
	// rejected as implausible (see TempNotReported / TempPlausible in temp.go).
	if !TempNotReported(dev.TempC) && !TempPlausible(dev.TempC, TempCeilNVMe) {
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
	// Temperature: SATA HDD/SSD operating + storage range; the garbage path
	// reports thousands of degrees (see TempPlausible in temp.go). smartctl
	// reports SATA temp in Celsius (ATA attr 194), so the 0-Kelvin sentinel
	// doesn't arise here — no exemption, unlike the NVMe path.
	if !TempPlausible(float64(dev.TempC), TempCeilNVMe) {
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

func checkNVMe(n models.NVMeInfo) []models.Insight { //nolint:funlen,cyclop // NOSONAR — NVMe + SATA/SAS checks — flat registry of independent per-drive checks
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
				[]string{inspectNVMEPrefix + dev.Name},
			))
		}
		if dev.MediaErrors > 0 {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s has %d media error(s) — data integrity risk", dev.Name, dev.MediaErrors),
				[]string{inspectNVMEPrefix + dev.Name},
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
				[]string{inspectNVMEPrefix + dev.Name},
			))
		} else if dev.AvailableSparePct > 0 && dev.AvailableSparePct < 20 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s spare capacity low at %d%%", dev.Name, dev.AvailableSparePct),
				[]string{inspectNVMEPrefix + dev.Name},
			))
		}
		if dev.PercentageUsed >= 90 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s wear at %d%% — consider replacement planning", dev.Name, dev.PercentageUsed),
				[]string{inspectNVMEPrefix + dev.Name},
			))
		}
		if dev.TempC >= 70 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s temperature %g°C — elevated for NVMe", dev.Name, dev.TempC),
				[]string{inspectNVMEPrefix + dev.Name},
			))
		}
		if dev.UnsafeShutdowns > 100 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d unsafe shutdown(s) — power cuts risk filesystem corruption", dev.Name, dev.UnsafeShutdowns),
				[]string{inspectNVMEPrefix + dev.Name, "to inspect: nvme list", "to fix: ensure clean shutdowns, check UPS"},
			))
		}
		if dev.PowerOnHours > 35000 {
			// Power-on hours is age, not wear — a long-lived enterprise/healthy drive
			// is fine. Real endurance is PercentageUsed / AvailableSpare (checked above),
			// so this is INFO context, not a WARN.
			out = append(out, insight("INFO", "Drives",
				fmt.Sprintf("%s has %d power-on hours (~%.1f years) — age only; wear is tracked via percentage-used/spare, not hours", dev.Name, dev.PowerOnHours, float64(dev.PowerOnHours)/8760),
				[]string{inspectNVMEPrefix + dev.Name},
			))
		}
	}

	// NVMe drives detected via sysfs but with no SMART log read. Surface this
	// rather than letting the drive default to a confident "healthy" — health was
	// never verified. Split by WHY it was unread so the remediation is correct: a
	// root-gated read on a non-root run must NOT say "install nvme-cli" (the tool
	// is usually already there; the user just needs sudo). Validated on a SLES 16
	// arm64 EC2 box where nvme-cli was installed but health wrongly told the
	// non-root operator to install it.
	var unreadRoot, unreadAbsent, unreadErr []string
	for _, dev := range n.Devices {
		if dev.SmartRead {
			continue
		}
		switch dev.SmartUnreadReason {
		case "needs_root":
			unreadRoot = append(unreadRoot, dev.Name)
		case "error":
			unreadErr = append(unreadErr, dev.Name)
		default: // "tool_absent" or empty (older captures) → historical default
			unreadAbsent = append(unreadAbsent, dev.Name)
		}
	}
	if len(unreadRoot) > 0 {
		out = append(out, insight("INFO", "Drives",
			fmt.Sprintf("%d NVMe drive(s) detected but SMART health not read (%s) — running unprivileged (nvme smart-log needs root)",
				len(unreadRoot), strings.Join(unreadRoot, ", ")),
			[]string{
				"to fix: re-run as root — NVMe SMART reads require privilege (sudo dsd health)",
				"note: drive presence is known; wear, media errors, and spare capacity are unverified",
			},
		))
	}
	if len(unreadAbsent) > 0 {
		out = append(out, insight("INFO", "Drives",
			fmt.Sprintf("%d NVMe drive(s) detected but SMART health not read (%s) — nvme-cli not installed",
				len(unreadAbsent), strings.Join(unreadAbsent, ", ")),
			[]string{
				"to fix: install nvme-cli  (apt install nvme-cli  /  dnf install nvme-cli  /  zypper install nvme-cli)",
				"note: drive presence is known; wear, media errors, and spare capacity are unverified",
			},
		))
	}
	if len(unreadErr) > 0 {
		out = append(out, insight("INFO", "Drives",
			fmt.Sprintf("%d NVMe drive(s) detected but SMART health not read (%s) — nvme smart-log failed",
				len(unreadErr), strings.Join(unreadErr, ", ")),
			[]string{
				inspectNVMEPrefix + unreadErr[0],
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
				inspectNVMEPrefix + implausible[0],
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
	var sataNeedsRoot, sataNoSmart, sataImplausible []string
	for _, dev := range n.SATADevices {
		// smartctl could not read this drive's SMART — it errored (permission /
		// non-root, transient) or returned no smart_status (USB bridge, RAID/HBA
		// member, virtual disk). Either way health is UNVERIFIED → surface it (INFO),
		// do NOT silently skip: a silent skip let the inline summary count the drive
		// as healthy, a non-root false-OK validated on pve01 (smartctl needs root, so
		// an unprivileged `dsd health` read "2 drives healthy" while SMART was never
		// read). Never a confident "drive may be failing" CRIT on an unverified drive.
		// Split by WHY: a permission failure says "re-run as root", a SMART-less
		// device (virtual disk / USB / RAID member) must NOT — claiming "running
		// unprivileged" while actually root is a false explanation (found on a real
		// VMware OL9 guest: virtual /dev/sda read SMART-less as root).
		if dev.Error != "" || !dev.SmartRead {
			if dev.SmartUnreadReason == "needs_root" {
				sataNeedsRoot = append(sataNeedsRoot, dev.Name)
			} else {
				sataNoSmart = append(sataNoSmart, dev.Name)
			}
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
				[]string{inspectSmartCtlPrefix + dev.Name},
			))
		}
		if dev.ReallocatedSectors > 0 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d reallocated sector(s) — early sign of drive failure", dev.Name, dev.ReallocatedSectors),
				[]string{inspectSmartCtlPrefix + dev.Name},
			))
		}
		if dev.PendingSectors > 0 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d pending sector(s) — unreadable sectors awaiting reallocation", dev.Name, dev.PendingSectors),
				[]string{inspectSmartCtlPrefix + dev.Name},
			))
		}
		if dev.UncorrectableErrors > 0 {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s has %d uncorrectable error(s) — data loss risk", dev.Name, dev.UncorrectableErrors),
				[]string{inspectSmartCtlPrefix + dev.Name},
			))
		}
		if dev.TempC >= 55 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s (%s) temperature %d°C — elevated for SATA drive", dev.Name, dev.Type, dev.TempC),
				[]string{inspectSmartCtlPrefix + dev.Name},
			))
		}
		if dev.PowerOnHours > 43800 {
			// Age, not health — enterprise/NAS HDDs routinely run 5+ years 24/7.
			// On its own this is not a failure signal; reallocated/pending sectors
			// and a failing SMART self-assessment (checked above) are. INFO context.
			out = append(out, insight("INFO", "Drives",
				fmt.Sprintf("%s (%s) has %d power-on hours (~%.1f years) — age only; not a failure signal on its own (check reallocated/pending sectors)", dev.Name, dev.Type, dev.PowerOnHours, float64(dev.PowerOnHours)/8760),
				[]string{inspectSmartCtlPrefix + dev.Name},
			))
		}
	}
	if len(sataImplausible) > 0 {
		out = append(out, insight("WARN", "Drives",
			fmt.Sprintf("%d SATA/SAS drive(s) returned implausible SMART data (%s) — health unverified, values rejected",
				len(sataImplausible), strings.Join(sataImplausible, ", ")),
			[]string{
				inspectSmartCtlPrefix + sataImplausible[0],
				"note: out-of-range temperature/sector-counts (vendor-encoded raw attributes, or virtual/USB-bridged SATA) — readings ignored to avoid a false drive-failure alarm",
			},
		))
	}
	if len(sataNeedsRoot) > 0 {
		out = append(out, insight("INFO", "Drives",
			fmt.Sprintf("%d SATA/SAS drive(s) detected but SMART health not read (%s) — running unprivileged (smartctl needs root)",
				len(sataNeedsRoot), strings.Join(sataNeedsRoot, ", ")),
			[]string{
				"to fix: re-run as root — SMART reads require privilege (sudo dsd health)",
				"to inspect: smartctl -a <device>  (try -d sat / -d cciss,N for controllers)",
				"note: drive presence is known; SMART health, wear, and errors are unverified",
			},
		))
	}
	if len(sataNoSmart) > 0 {
		out = append(out, insight("INFO", "Drives",
			fmt.Sprintf("%d SATA/SAS drive(s) detected but no SMART data exposed (%s) — a virtual disk, or a drive behind a RAID/HBA controller or USB bridge that doesn't pass SMART through",
				len(sataNoSmart), strings.Join(sataNoSmart, ", ")),
			[]string{
				inspectSmartCtlPrefix + sataNoSmart[0] + "  (try -d sat / -d cciss,N for controllers)",
				"note: drive presence is known; SMART health, wear, and errors are unverified — virtual disks expose none",
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
				fmt.Sprintf(inspectZPoolStatusFmt, p.Name),
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
			fmt.Sprintf(inspectZPoolStatusFmt, p.Name),
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
				fmt.Sprintf(inspectZPoolEventsFmt, pool.Name),
				"note: replace failed vdev and run: zpool replace <pool> <old> <new>",
				"note: data is at risk — restore redundancy immediately",
			},
		))
	case "FAULTED":
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s is FAULTED — pool may be unrecoverable", pool.Name),
			[]string{
				fmt.Sprintf(inspectZPoolStatusFmt, pool.Name),
				"note: FAULTED means pool was taken offline due to unrecoverable error",
				"note: import with: zpool import -F <pool>  (force recovery, may lose data)",
			},
		))
	case "SUSPENDED":
		// SUSPENDED is the most severe operational state: too many devices were lost
		// and the pool's I/O is halted (failmode=wait), so every read/write blocks. It
		// was missing from this switch — and a pool can suspend before it records any
		// R/W/C error counter, so the vdev-error path doesn't catch it either → it
		// rendered green. Treat it as a hard CRIT.
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s is SUSPENDED — I/O is halted (too many devices lost); all access to the pool blocks", pool.Name),
			[]string{
				fmt.Sprintf(inspectZPoolStatusFmt, pool.Name),
				fmt.Sprintf(inspectZPoolEventsFmt, pool.Name),
				"note: restore the missing devices, then: zpool clear " + pool.Name,
			},
		))
	case "REMOVED", "UNAVAIL", "OFFLINE":
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s state: %s", pool.Name, pool.State),
			[]string{
				fmt.Sprintf(inspectZPoolStatusFmt, pool.Name),
				fmt.Sprintf(inspectZPoolEventsFmt, pool.Name),
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
				fmt.Sprintf(inspectZPoolStatusFmt, pool.Name),
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
					fmt.Sprintf(inspectLVSFmt, pool.VG, pool.Name),
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
					fmt.Sprintf(inspectLVSFmt, pool.VG, pool.Name),
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
		// A fully-allocated VG is NOT a fault — it's the universal default-install
		// layout: root+swap (or the thin `data` pool) take the whole VG, leaving 0
		// free extents by design. The §O.1 fix carved out thin-pool-backed VGs, but
		// the same is true for plain LVM — a default CentOS/RHEL/Alma/Rocky/Ubuntu
		// install leaves VFree=0 with the root filesystem only ~40% used. The number
		// that signals real pressure is the FILESYSTEM fill (scored by the Disk
		// check) and the thin pool's data/metadata fill (scored above) — never the
		// VG's free extents. So a near-full VG is INFO ("no room to extend/snapshot
		// without adding a PV"), not a CRIT/WARN that falsely flips the verdict on
		// every stock install. (§O.1 widened — found live on a CentOS Stream 8 guest
		// whose VG `cs` was 100% allocated with the root FS at 38%.)
		if LVMVGFullLevel(vg.FreePct) != "" && !VGBacksThinPool(l.ThinPools, vg.Name) {
			out = append(out, insight("INFO", "LVM",
				fmt.Sprintf("volume group %s is fully allocated (%.0f%% used, %.1f GB free of %.1f GB) — normal for a default install; each LV's filesystem fill is what matters (see Disk)",
					vg.Name, 100-vg.FreePct, vg.FreeGB, vg.SizeGB),
				[]string{
					"note: a fully-allocated VG is the standard layout (root+swap take the whole VG) — not a fault on its own",
					fmt.Sprintf("to grow an LV or snapshot later, add a PV: pvcreate /dev/<disk> && vgextend %s /dev/<disk>", vg.Name),
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
					fmt.Sprintf(inspectLVSFmt, snap.VG, snap.Name),
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
	if d.Unverified {
		// DRBD 9 present but resource state unreadable (netlink needs root). Say so —
		// never omit (a split-brain/diskless resource must not hide behind silence).
		return []models.Insight{insight("INFO", "DRBD",
			"DRBD 9 present — resource state needs root (drbdsetup status uses netlink/CAP_NET_ADMIN)",
			[]string{"to verify: sudo drbdsetup status --json all   (or run dsd as root)"})}
	}
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
	case "WFConnection", "Connecting":
		// Waiting for connection — peer may be down or network issue. DRBD 8.x
		// reports "WFConnection"; DRBD 9.x reports "Connecting" for the same state
		// (a node retrying an unreachable peer sits here indefinitely), so both map
		// to the same waiting-for-peer WARN.
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: waiting for peer connection (%s) — peer may be down", name, res.ConnState),
			[]string{
				fmt.Sprintf(inspectDRBDStatusFmt, name),
				"to inspect: ping <peer-ip>",
				"to inspect: dmesg | grep -i drbd",
			},
		))
	case "Disconnecting":
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: disconnecting from peer", name),
			[]string{fmt.Sprintf(inspectDRBDStatusFmt, name)},
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
	case "Unconnected", "Timeout", "BrokenPipe", "NetworkFailure", "ProtocolError", "TearDown":
		// The peer link is down or failing — replication isn't active, so the
		// resource has no redundancy. These were previously unhandled (no default
		// case), so a dead replication link read as healthy. (Connected and the
		// benign transients VerifyS/T / Ahead / Behind / PausedSync are deliberately
		// not flagged here to avoid false alarms.)
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: connection state %s — peer link down/failing, replication not active", name, res.ConnState),
			[]string{
				fmt.Sprintf(inspectDRBDStatusFmt, name),
				"to inspect: ping <peer-ip>; check the replication network",
				"note: the resource is running without redundancy until the link recovers",
			},
		))
	}

	// Disk state — local disk health
	switch res.LocalDisk {
	case "Failed":
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: local disk state FAILED — underlying device has errors", name),
			[]string{
				fmt.Sprintf(inspectDRBDStatusFmt, name),
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
					fmt.Sprintf(inspectDRBDStatusFmt, name),
					fmt.Sprintf("to force sync: drbdadm -- --overwrite-data-of-peer primary %s", name),
					"warning: only use --overwrite-data-of-peer if you are certain this node has correct data",
				},
			))
		}
	case "Outdated":
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: local disk OUTDATED — peer has newer data", name),
			[]string{
				fmt.Sprintf(inspectDRBDStatusFmt, name),
				"note: disk will sync automatically when peer connection is restored",
			},
		))
	case "Diskless", "DUnknown":
		// No usable local backing device (lost disk, or never attached). Previously
		// unhandled → read healthy. WARN rather than CRIT because a deliberate
		// diskless client is a valid (if unusual) configuration.
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: local disk state %s — no usable local backing device, serving over the network only", name, res.LocalDisk),
			[]string{
				fmt.Sprintf(inspectDRBDStatusFmt, name),
				"to inspect: dmesg | grep -i drbd   (check whether the backing device failed)",
				fmt.Sprintf("to reattach (if intended): drbdadm attach %s", name),
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

func checkDisk(disk models.DiskInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	// A device mounted read-write at any mountpoint cannot also have been dropped to
	// read-only by a kernel I/O-error remount — that flips the whole block device to
	// ro at once. So a read-only mount whose backing device is ALSO mounted
	// read-write elsewhere is an intentional read-only BIND mount, not an error
	// remount (e.g. NixOS binds /nix/store ro off the rw root for immutability;
	// found on NixOS 25.05, 2026-06-30). Collect the rw device set up front so the
	// ro check below can exclude these without hardcoding any distro.
	rwDevices := make(map[string]bool)
	for _, fs := range disk.Filesystems {
		if !fs.ReadOnly && isWritableOnDiskFS(fs.FSType) {
			rwDevices[fs.Device] = true
		}
	}
	for _, fs := range disk.Filesystems {
		// Inherently read-only image filesystems (iso9660, squashfs, erofs,
		// cramfs) are packed to capacity at build time — 100% used is their
		// normal state and no admin action can free space. Skip usage/inode
		// scoring for these to avoid a guaranteed false CRIT on every live-USB
		// /cdrom, snap-backed squashfs, or AppImage mount. The read-only
		// remount check below still runs (handled by its own fstype allowlist).
		inherentRO := IsInherentlyReadOnlyFS(fs.FSType)
		if !inherentRO {
			if l := levelPct(fs.UsedPct, thresh.DiskWarnPct, thresh.DiskCritPct); l != "" {
				hints := []string{"to inspect: df -h", fmt.Sprintf("to inspect: du -sh %s/* 2>/dev/null | sort -h | tail -20", fs.Mount)}
				// /boot filling up is almost always old kernel images after upgrades.
				// Show distro-specific cleanup command based on detected package manager.
				if fs.Mount == "/boot" {
					bootHints := []string{
						"to inspect: df -h /boot",
						"to inspect: ls -lh /boot/vmlinuz* /boot/initramfs* /boot/initrd*",
					}
					switch thresh.PackageManager {
					case "dnf":
						bootHints = append(bootHints,
							"to inspect: rpm -q kernel",
							"to fix:     dnf remove --oldinstallonly --setopt installonly_limit=2",
						)
					case "apt":
						bootHints = append(bootHints,
							"to fix: apt autoremove --purge",
						)
					case "zypper":
						bootHints = append(bootHints,
							"to fix: zypper packages --orphaned | grep kernel",
						)
					case "pacman":
						bootHints = append(bootHints,
							"to inspect: pacman -Q linux",
							"to fix:     pacman -R <old-kernel-packages>",
						)
					default:
						// Unknown package manager — show all options
						bootHints = append(bootHints,
							"to fix (dnf):    dnf remove --oldinstallonly --setopt installonly_limit=2",
							"to fix (apt):    apt autoremove --purge",
							"to fix (zypper): zypper packages --orphaned | grep kernel",
							"to fix (pacman): pacman -Q linux  # then pacman -R <old-kernels>",
						)
					}
					hints = bootHints
				}
				hints = append(hints, busyProcessHints(fs)...)
				msg := fmt.Sprintf("disk usage at %.0f%% on %s (%s)", fs.UsedPct, fs.Mount, fs.Device)
				if n := len(fs.BusyProcesses); n > 0 {
					msg += fmt.Sprintf(" — %d process(es) have files open", n)
				}
				out = append(out, insight(l, "Disk", msg, hints))
			}
			if l := levelPct(fs.InodesUsedPct, thresh.DiskWarnPct, thresh.DiskCritPct); l != "" {
				out = append(out, insight(l, "Disk",
					fmt.Sprintf("inode usage at %.0f%% on %s", fs.InodesUsedPct, fs.Mount),
					[]string{"to inspect: df -i", fmt.Sprintf("to inspect: find %s -xdev -printf '%%h\\n' | sort | uniq -c | sort -rn | head -20", fs.Mount)},
				))
			}
		}
		// A writable on-disk filesystem mounted read-only is almost always an
		// error remount: the kernel hit I/O or metadata errors and dropped the fs
		// to ro to prevent further damage, so apps silently fail to write. dsd
		// captured this but never surfaced it (a serious missed condition). The
		// on-disk-fstype allowlist avoids flagging inherently/intentionally ro
		// mounts (squashfs, iso9660, overlay, ro bind mounts).
		// On an immutable OS (ostree / transactional-update / MicroOS / Leap Micro /
		// SteamOS) the immutable-infrastructure mounts are read-only snapshots BY
		// DESIGN, not error remounts — skip the WARN for them (collector sets
		// ImmutableRootFS, replay-faithful). On a transactional/SteamOS host that is
		// `/` itself; on ostree (Fedora CoreOS/Silverblue) `/` stays writable but the
		// physical root `/sysroot`, plus `/boot` and the `/usr` bind, are mounted ro —
		// so a "/-only" suppression false-WARNed those on FCOS (2026-06-29). A genuine
		// I/O-error remount of a DATA mount (e.g. /var, /home) still WARNs everywhere.
		immutableInfra := disk.ImmutableRootFS && isImmutableInfraMount(fs.Mount)
		// A ro mount of a device that is mounted rw elsewhere is an intentional ro
		// bind, not an I/O-error remount (see rwDevices comment above).
		roBindOfRWDevice := fs.ReadOnly && rwDevices[fs.Device]
		if fs.ReadOnly && isWritableOnDiskFS(fs.FSType) && !immutableInfra && !roBindOfRWDevice {
			hints := make([]string, 0, 5)
			hints = append(hints,
				"to inspect: dmesg | grep -iE 'remount|i/o error|ext4-fs error|xfs.*(error|corrupt)|btrfs.*error'",
				fmt.Sprintf("to inspect: mount | grep ' %s '", fs.Mount),
				fmt.Sprintf("after fixing the cause: mount -o remount,rw %s", fs.Mount),
				"note: intentionally read-only mounts (immutable OS, ro bind mounts) can ignore this",
			)
			hints = append(hints, busyProcessHints(fs)...)
			out = append(out, insight("WARN", "Disk",
				fmt.Sprintf("filesystem %s (%s on %s) is mounted READ-ONLY — if it should be writable, the kernel likely remounted it after an I/O error", fs.Mount, fs.FSType, fs.Device),
				hints,
			))
		}
		out = append(out, checkDiskGrowth(fs)...)
	}
	out = append(out, checkDiskExtras(disk)...)
	return out
}

// checkDiskGrowth flags a filesystem whose backing device (partition / LV) is
// meaningfully larger than the filesystem on it — the classic "grew the VMDK/EBS
// volume (or lvextend'd) but forgot resize2fs/xfs_growfs", leaving the extra
// space unusable until someone notices the disk "full" at the old size. A
// universal VM/cloud ops mistake, not distro-specific. Conservative on purpose
// (see thresholds); DeviceSizeGB==0 means the device size is unknown (non-Linux,
// or no sysfs node) and is skipped — never guessed.
func checkDiskGrowth(fs models.FilesystemInfo) []models.Insight {
	if fs.DeviceSizeGB <= 0 || fs.TotalGB <= 0 || !isWritableOnDiskFS(fs.FSType) {
		return nil
	}
	gap := fs.DeviceSizeGB - fs.TotalGB
	if gap < diskGrowthMinGapGB || gap < diskGrowthMinGapFrac*fs.DeviceSizeGB {
		return nil
	}
	return []models.Insight{insight("WARN", "Disk",
		fmt.Sprintf("filesystem %s (%s) is %.0f GB but its device %s is %.0f GB — the device was grown but the filesystem was not resized, so ~%.0f GB is unusable",
			fs.Mount, fs.FSType, fs.TotalGB, fs.Device, fs.DeviceSizeGB, gap),
		diskGrowthHints(fs))}
}

// checkBtrfsVolume turns one btrfs volume's health into insights: missing devices
// are a DEGRADED CRIT; read/write I/O errors are a failing-device CRIT (not
// scrub-correctable); corruption/checksum errors alone are a WARN (often
// scrub-correctable).
func checkBtrfsVolume(v models.BtrfsVolume) []models.Insight {
	if v.MissingDevs > 0 {
		return []models.Insight{insight("CRIT", "Disk",
			fmt.Sprintf("btrfs %s is DEGRADED — %d missing device(s), data at risk", v.MountPoint, v.MissingDevs),
			[]string{
				fmt.Sprintf("to inspect: btrfs filesystem show %s", v.MountPoint),
				fmt.Sprintf(inspectBtrfsStatsFmt, v.MountPoint),
				"to fix:     reattach missing device and run: btrfs device scan",
			},
		)}
	}
	// btrfs run unprivileged can't open the block devices, so `btrfs filesystem show`
	// prints every present device as `size 0 ... MISSING` — the device-state read
	// failed, it is NOT a missing device. Surface that honestly as INFO rather than the
	// false DEGRADED CRIT it used to raise (every btrfs filesystem on a non-root run).
	if v.DevReadUnverified {
		return []models.Insight{insight("INFO", "Disk",
			fmt.Sprintf("btrfs %s device state could not be verified — run as root (devices show unreadable without privilege)", v.MountPoint),
			[]string{
				fmt.Sprintf("to inspect: sudo btrfs filesystem show %s", v.MountPoint),
				fmt.Sprintf("to inspect: sudo btrfs device stats %s", v.MountPoint),
				"note: an unprivileged `btrfs filesystem show` reports present devices as MISSING — not an actual fault",
			},
		)}
	}
	// `btrfs device stats` couldn't be read, so the per-device read/write/corruption
	// counters were never inspected — Status defaulted to "healthy". Don't pass that
	// as a clean OK. (When errors WERE found, StatsRead is true, so this won't fire.)
	if !v.StatsRead {
		return []models.Insight{insight("INFO", "Disk",
			fmt.Sprintf("btrfs %s device error counters not read — run as root: btrfs device stats %s", v.MountPoint, v.MountPoint),
			[]string{fmt.Sprintf(inspectBtrfsStatsFmt, v.MountPoint)},
		)}
	}
	if v.Status != "errors" {
		return nil
	}

	var ioErrs, corruptErrs int64
	for _, d := range v.Devices {
		ioErrs += d.ReadErrs + d.WriteErrs
		corruptErrs += d.CorruptErrs
	}
	if ioErrs > 0 {
		// Read/write I/O errors mean the underlying device is failing (bad blocks,
		// cabling, controller) — not scrub-correctable. CRIT.
		return []models.Insight{insight("CRIT", "Disk",
			fmt.Sprintf("btrfs %s has %d device I/O error(s) — failing storage or cabling", v.MountPoint, ioErrs),
			[]string{
				fmt.Sprintf(inspectBtrfsStatsFmt, v.MountPoint),
				"to inspect: dmesg | grep -i 'btrfs\\|i/o error'",
				"note: back up data now — I/O errors are not scrub-correctable",
			},
		)}
	}
	// Corruption/checksum errors only — often correctable via scrub. WARN.
	return []models.Insight{insight("WARN", "Disk",
		fmt.Sprintf("btrfs %s has %d checksum/corruption error(s) — may be scrub-correctable", v.MountPoint, corruptErrs),
		[]string{
			fmt.Sprintf(inspectBtrfsStatsFmt, v.MountPoint),
			fmt.Sprintf("to fix:     btrfs scrub start %s  (check for correctable errors)", v.MountPoint),
		},
	)}
}

func checkDiskExtras(disk models.DiskInfo) []models.Insight {
	var out []models.Insight
	if disk.SteamOS != nil {
		out = append(out, checkSteamOSDisk(disk.SteamOS)...)
	}
	// SMART health
	for _, d := range disk.Drives {
		if d.SMART == nil || d.SMART.Error != "" {
			continue
		}
		if !d.SMART.Healthy {
			out = append(out, insight("CRIT", "Disk",
				fmt.Sprintf("%s SMART health FAILED — drive may be failing, back up immediately", d.Name),
				[]string{
					fmt.Sprintf("to inspect: smartctl -a /dev/%s", d.Name),
					"to inspect: dmesg | grep -i 'error\\|failed\\|reset'",
				},
			))
		} else if d.SMART.PercentUsed >= 90 {
			out = append(out, insight("WARN", "Disk",
				fmt.Sprintf("%s NVMe wear at %d%% — drive approaching end of life", d.Name, d.SMART.PercentUsed),
				[]string{fmt.Sprintf("to inspect: smartctl -A /dev/%s", d.Name)},
			))
		} else if d.SMART.MediaErrors > 0 {
			out = append(out, insight("WARN", "Disk",
				fmt.Sprintf("%s has %d media error(s) — monitor closely", d.Name, d.SMART.MediaErrors),
				[]string{fmt.Sprintf("to inspect: smartctl -a /dev/%s", d.Name)},
			))
		}
	}
	// btrfs volume health — missing devices are a silent CRIT
	for _, v := range disk.BtrfsVolumes {
		out = append(out, checkBtrfsVolume(v)...)
	}
	// ZFS — a live mount exists (zfsGate) but `zpool list` failed, so no pool was read.
	if disk.ZFSListReadFailed {
		out = append(out, insight("INFO", "Disk",
			"ZFS mount present but pools could NOT be verified — `zpool list` failed (run as root?)",
			[]string{"to inspect: zpool list", "to inspect: zpool status"},
		))
	}
	// ZFS pool health is scored by checkZFS (the dedicated ZFSCollector), NOT here.
	// Both collectors gate on the `zpool` binary, so whenever the DiskCollector sees
	// ZFS pools the ZFSCollector has also run — scoring them here too produced TWO
	// insights per pool (a "Disk" one and a "ZFS" one) AND a verdict flip, because
	// "never scrubbed" was INFO on this path but WARN in checkZFS. checkZFS is the
	// richer scorer (SUSPENDED/REMOVED/UNAVAIL states, vdev errors, StatusReadFailed,
	// scrub age), so it owns ZFS; this path defers to avoid the double-score.
	return out
}

func checkHBA(hba models.HBAInfo) []models.Insight {
	if len(hba.Ports) == 0 {
		return nil
	}
	var out []models.Insight
	for _, p := range hba.Ports {
		state := strings.ToLower(p.PortState)
		switch {
		case state == "":
			// port_state was unreadable (sysfs read failed). Don't whitelist it as
			// healthy — the inline renderer already counts it as not-online, so a
			// silent OK here was a sibling-divergence false-OK. Surface it as unknown.
			out = append(out, insight("WARN", "HBA",
				fmt.Sprintf("FC port %s state could not be read — storage path health unknown", p.Name),
				[]string{
					"to inspect: cat /sys/class/fc_host/" + p.Name + "/port_state",
					"to inspect: systool -c fc_host -v",
				},
			))
		case state != "online" && state != "linkup":
			out = append(out, insight("CRIT", "HBA",
				fmt.Sprintf("FC port %s is %s — storage path lost", p.Name, p.PortState),
				[]string{
					"to inspect: cat /sys/class/fc_host/" + p.Name + "/port_state",
					"to inspect: systool -c fc_host -v",
					"note: check SFP cable, switch zoning, and target port",
				},
			))
		}
		// link_failure_count / loss_of_sync_count are cumulative since-boot sysfs
		// counters that never decay, so a single historical transient (a cable reseat
		// or switch reboot at install) would pin a permanent WARN on an otherwise
		// healthy fabric with LinkFailures > 0. Require a non-trivial count (matching
		// the existing LossOfSync threshold) so only a genuinely flapping link warns.
		// (A two-snapshot rate would be more precise but needs real FC hardware to
		// validate; this static threshold strictly reduces the historical-transient
		// false-alarm.)
		if p.LinkFailures > 10 || p.LossOfSync > 100 {
			out = append(out, insight("WARN", "HBA",
				fmt.Sprintf("FC port %s: %d link failures, %d loss-of-sync — check fibre and SFP",
					p.Name, p.LinkFailures, p.LossOfSync),
				[]string{
					"to inspect: cat /sys/class/fc_host/" + p.Name + "/statistics/link_failure_count",
					"to inspect: check SFP module and fibre cable",
				},
			))
		}
	}
	return out
}

func checkMultipath(m models.MultipathInfo) []models.Insight {
	if !m.Available {
		return nil
	}
	// multipathd is running but its path table could not be read (both `multipathd
	// show paths` and `multipath -l` failed) — Devices is empty for a reason other
	// than "no maps configured", so don't let it pass as a silent OK.
	if m.Status == "error" {
		reason := m.StatusReason
		if reason == "" {
			reason = "multipath paths unreadable"
		}
		return []models.Insight{insight("WARN", "Multipath",
			"multipath path health could NOT be verified — "+reason,
			[]string{
				inspectMultipath,
				"to inspect: multipath -l   (run as root)",
			},
		)}
	}
	if len(m.Devices) == 0 {
		return nil
	}
	var out []models.Insight
	for _, dev := range m.Devices {
		if dev.FailedPaths == 0 {
			continue
		}
		label := mpathLabel(dev)
		if dev.ActivePaths == 0 {
			out = append(out, insight("CRIT", "Multipath",
				fmt.Sprintf("%s: all paths failed — device unavailable", label),
				[]string{
					inspectMultipath,
					"to inspect: multipath -l",
					"to inspect: check SAN fabric and HBA",
				},
			))
		} else {
			out = append(out, insight("WARN", "Multipath",
				fmt.Sprintf("%s: %d/%d paths failed — running degraded",
					label, dev.FailedPaths, dev.TotalPaths),
				[]string{
					inspectMultipath,
					"to inspect: multipath -l",
					fmt.Sprintf("to inspect: cat /sys/block/%s/dm/state", dev.DM),
					"note: replace failed path before removing redundant one",
				},
			))
		}
	}
	return out
}

func checkCeph(c models.CephInfo) []models.Insight {
	if !c.Available {
		// Unprivileged run: `ceph health` failed only because the admin keyring is
		// root-only, not because the cluster is down. Surface "could not verify",
		// never a false CRIT (the run-as-both rule).
		if c.NeedsRoot {
			return []models.Insight{insight("INFO", "Ceph",
				"Ceph cluster state not verified — `ceph health` needs root (admin keyring is root-only)",
				[]string{"to verify: sudo ceph -s   (or run dsd as root)"})}
		}
		// Configured for a cluster but `ceph health` failed → the cluster is
		// unreachable from a node that's part of it. That's a real outage and must
		// surface, not be silently gated off like a bare client binary.
		if c.Configured {
			return []models.Insight{insight("CRIT", "Ceph",
				"Ceph cluster unreachable — node is configured for a cluster but `ceph health` failed",
				[]string{
					"to inspect: ceph -s   (or: ceph health detail)",
					"to check mons: systemctl status ceph-mon.target",
					"note: a stuck/unreachable mon quorum freezes all RBD/CephFS I/O",
				})}
		}
		return nil
	}
	switch c.Health {
	case "HEALTH_ERR":
		msg := "Ceph cluster health is ERROR"
		if len(c.Summary) > 0 {
			msg = "Ceph: " + c.Summary[0]
		}
		return []models.Insight{insight("CRIT", "Ceph", msg,
			[]string{"to inspect: ceph health detail", "to inspect: ceph osd tree"})}
	case "HEALTH_WARN":
		msg := "Ceph cluster health is WARN"
		if len(c.Summary) > 0 {
			msg = "Ceph: " + c.Summary[0]
		}
		return []models.Insight{insight("WARN", "Ceph", msg,
			[]string{"to inspect: ceph health detail", "to inspect: ceph osd stat"})}
	case "HEALTH_UNKNOWN":
		// `ceph health detail` ran but returned no parseable status — surface that
		// rather than letting an empty Health read as a healthy cluster.
		return []models.Insight{insight("WARN", "Ceph",
			"Ceph cluster health could not be read — `ceph health detail` returned no parseable status",
			[]string{"to inspect: ceph health detail", "to inspect: ceph -s"})}
	}
	downOSDs := c.OSDTotal - c.OSDUp
	if downOSDs > 0 {
		return []models.Insight{insight("WARN", "Ceph",
			fmt.Sprintf("%d OSD(s) down (%d/%d up)", downOSDs, c.OSDUp, c.OSDTotal),
			[]string{"to inspect: ceph osd tree", "to inspect: ceph osd stat"})}
	}
	return nil
}

func checkISCSI(i models.ISCSIInfo) []models.Insight {
	// Active sessions exist but their state couldn't be read unprivileged (the per-
	// session sysfs fields iscsiadm reads are root-only). Say "needs root" — never
	// silently omit, which would hide a failed/reconnecting session (the run-as-both
	// rule).
	if i.NeedsRoot {
		return []models.Insight{insight("INFO", "iSCSI",
			"iSCSI session(s) present but their state needs root (iscsiadm reads root-only sysfs fields)",
			[]string{"to verify: sudo iscsiadm -m session -P 1   (or run dsd as root)"})}
	}
	if !i.Available || len(i.Sessions) == 0 {
		return nil
	}
	if i.FailedCount == 0 {
		return nil
	}
	return []models.Insight{insight("CRIT", "iSCSI",
		fmt.Sprintf("%d iSCSI session(s) not logged in — storage path lost", i.FailedCount),
		[]string{
			"to inspect: iscsiadm -m session",
			"to fix:     iscsiadm -m node --loginall=all",
			"to inspect: check network connectivity to iSCSI portal",
		})}
}

// busyProcessHints formats fs.BusyProcesses (populated by the collector's
// fuser/proc-fd busy-filesystem scan, Spec 4 addendum §4-add) into extra hint
// lines for a disk-usage or read-only-remount insight — an admin blocked by
// "device or resource busy" on unmount needs to know what to stop first.
func busyProcessHints(fs models.FilesystemInfo) []string {
	if len(fs.BusyProcesses) == 0 {
		if fs.BusyCheckNeedsRoot {
			return []string{"busy-process scan ran unprivileged — PIDs owned by other users may be invisible; rerun as root for a complete list"}
		}
		return nil
	}
	writers := 0
	for _, p := range fs.BusyProcesses {
		if p.Write {
			writers++
		}
	}
	hints := make([]string, 0, len(fs.BusyProcesses)+2)
	riskNote := ""
	if len(fs.BusyProcesses) > 10 {
		riskNote = " — too many to unmount safely without stopping them first"
	}
	hints = append(hints, fmt.Sprintf("%d process(es) have %s open (%d writing)%s",
		len(fs.BusyProcesses), fs.Mount, writers, riskNote))
	for _, p := range fs.BusyProcesses {
		mode := "read"
		if p.Write {
			mode = "write"
		}
		hints = append(hints, fmt.Sprintf("PID %d  %s  user %s  (%s)", p.PID, p.Command, p.User, mode))
	}
	if fs.BusyCheckNeedsRoot {
		hints = append(hints, "busy-process scan ran unprivileged — PIDs owned by other users may be invisible; rerun as root for a complete list")
	}
	return hints
}

// isImmutableInfraMount reports whether a mount point is part of an immutable
// OS's read-only infrastructure (as opposed to a writable data mount). On
// ostree (Fedora CoreOS/Silverblue/Kinoite/IoT) the physical root `/sysroot`,
// `/boot`, and the `/usr` bind are ro by design; on transactional-update/MicroOS
// and SteamOS `/` itself is the ro snapshot. These never indicate an error
// remount on an immutable host. Data mounts (/var, /home, …) are deliberately
// excluded so a real ro-remount of writable state still WARNs.
func isImmutableInfraMount(mount string) bool {
	switch mount {
	case "/", "/sysroot", "/usr", "/boot", "/boot/efi", "/efi":
		return true
	}
	return false
}

// isWritableOnDiskFS reports whether a filesystem type is a normal read-write
// on-disk filesystem (so being mounted read-only is suspicious). Allowlist, not
// denylist, so squashfs/iso9660/overlay/tmpfs/etc. never trip the ro check.
func isWritableOnDiskFS(fsType string) bool {
	switch fsType {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs":
		return true
	}
	return false
}

// diskGrowthHints returns the filesystem-appropriate online-grow command. The
// device is already the right size (that is what the check detected), so only the
// filesystem needs growing — no growpart/parted step.
func diskGrowthHints(fs models.FilesystemInfo) []string {
	switch {
	case strings.HasPrefix(fs.FSType, "ext"):
		return []string{
			fmt.Sprintf("to fix: resize2fs %s", fs.Device),
			"note: resize2fs grows an ext2/3/4 filesystem online to fill its device",
		}
	case fs.FSType == "xfs":
		return []string{
			fmt.Sprintf("to fix: xfs_growfs %s", fs.Mount),
			"note: XFS grows online (mounted) and can only grow, never shrink",
		}
	case fs.FSType == "btrfs":
		return []string{fmt.Sprintf("to fix: btrfs filesystem resize max %s", fs.Mount)}
	default:
		return []string{fmt.Sprintf("to fix: grow the %s filesystem on %s to fill the device", fs.FSType, fs.Device)}
	}
}

// IsInherentlyReadOnlyFS reports whether a filesystem type is read-only by
// design (immutable image/packed formats). Such filesystems are full by
// construction: they are packed to capacity at build time and there is no
// admin action that can free space. A 100%-used iso9660 (live-USB /cdrom),
// squashfs (snap/AppImage backing), or erofs/cramfs image is the normal,
// healthy state — not a disk-pressure condition. Reporting it as CRIT/WARN
// is a false positive, so usage-level scoring skips these types.
func IsInherentlyReadOnlyFS(fsType string) bool {
	switch fsType {
	case "iso9660", "squashfs", "erofs", "cramfs":
		return true
	}
	return false
}

// mpathLabel renders a multipath device as "name (dm)", but collapses to just
// "name" when the dm device equals the name (the common case with
// user_friendly_names, where the alias IS the dm name → "mpathb (mpathb)") or
// when the dm field is empty.
func mpathLabel(dev models.MultipathDevice) string {
	if dev.DM == "" || dev.DM == dev.Name {
		return dev.Name
	}
	return fmt.Sprintf("%s (%s)", dev.Name, dev.DM)
}
