package analysis

import "github.com/keyorixhq/dashdiag/internal/platform"

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
}

func DefaultThresholds(env platform.CloudEnvironment) Thresholds {
	t := Thresholds{
		CPULoadWarnMultiplier: 0.7,
		CPULoadCritMultiplier: 0.9,

		RAMWarnPct:  80,
		RAMCritPct:  95,
		SlabWarnPct: 20,

		DiskWarnPct: 80,
		DiskCritPct: 90,

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

		ZombieWarnCount: 5,
		HungDStateCrit:  1,

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
