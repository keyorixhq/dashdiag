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
		SwapActivityWarn: 0,
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
