package analysis

import "github.com/keyorixhq/dashdiag/internal/platform"

// Default disk / filesystem / ZFS capacity thresholds (percent used). Exported as
// the single source of truth so the standalone `dsd disk` renderer classifies
// storage identically to `dsd health` — they had drifted (disk used 85/95, health
// 80/90), so the same volume could read OK in one command and WARN in the other.
const (
	DefaultDiskWarnPct = 80.0
	DefaultDiskCritPct = 90.0
)

// LVM thin-pool / snapshot / volume-group and Proxmox storage thresholds. Same
// single-source-of-truth rationale as the disk constants above: these facts are
// classified by BOTH a dedicated subcommand (`dsd disk`, `dsd pve`) and `dsd health`,
// and they had drifted — `dsd disk` warned on a thin pool at 70% / snapshot at 70% /
// VG under 15% free, and `dsd pve` on storage at 85%, while health used 80 / 80 / 10
// / 80 — so the same volume read WARN in one command and OK (or CRIT vs WARN) in the
// other (BUG-050 class). Both sides now go through the classifiers below.
const (
	LVMThinPoolWarnPct = 80.0
	LVMThinPoolCritPct = 90.0
	LVMSnapshotWarnPct = 80.0
	LVMSnapshotCritPct = 95.0 // snapshots tolerate slightly higher fill than pools before CRIT
	LVMVGFullWarnPct   = 90.0 // measured as % of VG capacity used, i.e. 100 - FreePct
	LVMVGFullCritPct   = 98.0
	PVEStorageWarnPct  = 80.0
	PVEStorageCritPct  = 90.0
)

// LVMThinPoolLevel classifies a thin-pool data-fill percentage as "CRIT"/"WARN"/"".
func LVMThinPoolLevel(dataPct float64) string {
	return levelPct(dataPct, LVMThinPoolWarnPct, LVMThinPoolCritPct)
}

// LVMSnapshotLevel classifies a snapshot data-fill percentage as "CRIT"/"WARN"/"".
func LVMSnapshotLevel(dataPct float64) string {
	return levelPct(dataPct, LVMSnapshotWarnPct, LVMSnapshotCritPct)
}

// LVMVGFullLevel classifies a volume group by how full it is. It takes the FREE
// percentage (as the collectors report it) and classifies the used percentage,
// so callers don't each re-derive 100-free and risk drifting again.
func LVMVGFullLevel(freePct float64) string {
	return levelPct(100-freePct, LVMVGFullWarnPct, LVMVGFullCritPct)
}

// PVEStorageLevel classifies a Proxmox storage pool used percentage as "CRIT"/"WARN"/"".
func PVEStorageLevel(usedPct float64) string {
	return levelPct(usedPct, PVEStorageWarnPct, PVEStorageCritPct)
}

type Thresholds struct {
	CPULoadWarnMultiplier float64
	CPULoadCritMultiplier float64

	RAMWarnPct  float64
	RAMCritPct  float64
	SlabWarnPct float64

	DiskWarnPct float64
	DiskCritPct float64

	SwapWarnPct      float64
	SwapCritPct      float64
	SwapActivityWarn float64
	SwapActivityCrit float64

	IOUtilWarnPctSSD float64
	IOUtilCritPctSSD float64
	IOAwaitWarnMsSSD float64
	IOAwaitCritMsSSD float64

	NTPOffsetWarnMs float64
	NTPOffsetCritMs float64

	FDSystemWarnPct float64
	FDSystemCritPct float64
	FDProcWarnPct   float64

	ZombieWarnCount int
	HungDStateCrit  int

	JournalSizeWarnGB float64
	JournalSizeCritGB float64

	SELinuxDenialsWarnPerHr int
	SELinuxDenialsCritPerHr int

	// PackageManager is detected at runtime from PackagesInfo and used to
	// show distro-specific fix commands in disk and other checks.
	// Values: "dnf", "apt", "zypper", "pacman", "brew", "" (unknown)
	PackageManager string

	// CPULoadPct is detected at runtime from CPUInfo and used to
	// contextualise thermal readings — high temp at low load = cooling issue.
	CPULoadPct float64
}

func DefaultThresholds(env platform.CloudEnvironment) Thresholds {
	t := Thresholds{
		CPULoadWarnMultiplier: 0.7,
		CPULoadCritMultiplier: 0.9,

		RAMWarnPct:  80,
		RAMCritPct:  95,
		SlabWarnPct: 20,

		DiskWarnPct: DefaultDiskWarnPct,
		DiskCritPct: DefaultDiskCritPct,

		SwapWarnPct:      20,
		SwapCritPct:      60,
		SwapActivityWarn: 50, // pages/s — below this is background churn, not a problem
		SwapActivityCrit: 100,

		IOUtilWarnPctSSD: 60,
		IOUtilCritPctSSD: 85,

		NTPOffsetWarnMs: 100,
		NTPOffsetCritMs: 500,

		FDSystemWarnPct: 80,
		FDSystemCritPct: 90,
		FDProcWarnPct:   80,

		// Defaults preserve the historical hardcoded behaviour: warn on any
		// zombie, CRIT at 5+ hung D-state processes. Overridable via policy
		// (zombie_warn_count / hung_d_state_crit).
		ZombieWarnCount: 1,
		HungDStateCrit:  5,

		JournalSizeWarnGB: 2,
		JournalSizeCritGB: 5,

		SELinuxDenialsWarnPerHr: 1,
		SELinuxDenialsCritPerHr: 10,
	}

	switch env {
	case platform.EnvAWSEBS, platform.EnvGCP, platform.EnvAzure:
		t.IOAwaitWarnMsSSD = 5
		t.IOAwaitCritMsSSD = 20
	case platform.EnvAWSNVMe, platform.EnvBareMetal:
		t.IOAwaitWarnMsSSD = 1
		t.IOAwaitCritMsSSD = 5
	default:
		t.IOAwaitWarnMsSSD = 2
		t.IOAwaitCritMsSSD = 10
	}

	return t
}

// ApplyContainerThresholds raises IO thresholds for container environments
// where storage is shared/virtualised and higher latency is expected.
func ApplyContainerThresholds(t *Thresholds) {
	// LXC/Docker containers on shared LVM or overlay storage typically see
	// 1-5ms await even when healthy — same ballpark as cloud EBS.
	if t.IOAwaitWarnMsSSD < 5 {
		t.IOAwaitWarnMsSSD = 5
	}
	if t.IOAwaitCritMsSSD < 20 {
		t.IOAwaitCritMsSSD = 20
	}
}
