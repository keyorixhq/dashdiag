package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-8 characterization tests for the large branchy heuristics: physical
// hardware (SMART/temp/wear/sectors + EDAC ECC), kernel security modules
// (SELinux policy validity, AppArmor), and workload-aware sysctl tuning.

// ── Hardware: SMART, temperature, wear, sectors, EDAC ─────────────────────────

func TestCheckHardware(t *testing.T) {
	// A drive that is present and healthy unless a field below makes it otherwise.
	drive := func(d models.HardwareDrive) models.HardwareInfo {
		d.Device = "/dev/sda"
		d.SmartctlAvailable = true
		d.SmartOK = true
		return models.HardwareInfo{Drives: []models.HardwareDrive{d}}
	}
	tests := []struct {
		name string
		h    models.HardwareInfo
		want string
	}{
		{"no hardware data is clean", models.HardwareInfo{}, ""},
		{"smartctl missing is INFO", models.HardwareInfo{Drives: []models.HardwareDrive{{Device: "/dev/sda"}}}, "INFO"},
		{"healthy drive emits OK", drive(models.HardwareDrive{Type: "sata", TempC: 35}), "OK"},
		{"smart failed is CRIT", models.HardwareInfo{Drives: []models.HardwareDrive{{Device: "/dev/sda", SmartctlAvailable: true, SmartOK: false}}}, "CRIT"},
		{"nvme critical temp is CRIT", drive(models.HardwareDrive{Type: "nvme", TempC: 85}), "CRIT"},
		{"nvme hot is WARN", drive(models.HardwareDrive{Type: "nvme", TempC: 72}), "WARN"},
		{"hdd critical temp is CRIT", drive(models.HardwareDrive{Type: "sata", TempC: 62}), "CRIT"},
		{"high wear is CRIT", drive(models.HardwareDrive{WearPct: 96}), "CRIT"},
		{"moderate wear is WARN", drive(models.HardwareDrive{WearPct: 85}), "WARN"},
		{"many reallocated sectors is CRIT", drive(models.HardwareDrive{ReallocatedSectors: 15}), "CRIT"},
		{"few reallocated sectors is WARN", drive(models.HardwareDrive{ReallocatedSectors: 3}), "WARN"},
		{"pending sectors is CRIT", drive(models.HardwareDrive{PendingSectors: 6}), "CRIT"},
		{"uncorrectable errors is CRIT", drive(models.HardwareDrive{UncorrectableErrors: 1}), "CRIT"},
		{"nvme media errors is CRIT", drive(models.HardwareDrive{MediaErrors: 12}), "CRIT"},
		{"drive read error is WARN", models.HardwareInfo{Drives: []models.HardwareDrive{{Device: "/dev/sda", SmartctlAvailable: true, Error: "scan timeout"}}}, "WARN"},
		{"EDAC uncorrected is CRIT", models.HardwareInfo{Memory: models.HardwareMemory{EDACAvailable: true, UncorrectedErrors: 1}}, "CRIT"},
		{"EDAC corrected is WARN", models.HardwareInfo{Memory: models.HardwareMemory{EDACAvailable: true, CorrectedErrors: 150}}, "WARN"},
		// Regression: a missing smartctl (synthetic SmartctlAvailable:false drive)
		// must NOT short-circuit the EDAC/ECC memory check that follows the drive loop.
		{"ECC fault surfaces even when smartctl is absent", models.HardwareInfo{
			Drives: []models.HardwareDrive{{SmartctlAvailable: false}},
			Memory: models.HardwareMemory{EDACAvailable: true, UncorrectedErrors: 1},
		}, "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkHardware(tt.h), tt.want)
		})
	}
}

// ── Kernel security (SELinux / AppArmor) ──────────────────────────────────────

func TestCheckKernelSecurity(t *testing.T) {
	// SELinux permissive with a fully-valid policy — no insight (the dontaudit
	// advisory only fires in enforcing mode).
	cleanPolicy := models.KernelSecurityInfo{
		SELinuxPresent: true, SELinuxMode: "permissive", SELinuxType: "targeted",
		SELinuxTypeValid: true, SELinuxPolicyDirOK: true, SELinuxPolicyPkgOK: true,
	}
	tests := []struct {
		name string
		mac  models.KernelSecurityInfo
		want string
	}{
		{"valid permissive policy is clean", cleanPolicy, ""},
		{
			// Enforcing with zero denials deliberately emits a dontaudit advisory:
			// "zero denials does not mean clean" — dontaudit rules can hide denials.
			name: "enforcing emits dontaudit advisory (INFO)",
			mac: models.KernelSecurityInfo{
				SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxType: "targeted",
				SELinuxTypeValid: true, SELinuxPolicyDirOK: true, SELinuxPolicyPkgOK: true,
			},
			want: "INFO",
		},
		{
			name: "invalid SELINUXTYPE is CRIT",
			mac:  models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxType: "bogus", SELinuxTypeValid: false},
			want: "CRIT",
		},
		{
			name: "pending relabel is WARN",
			mac: models.KernelSecurityInfo{
				SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxType: "targeted",
				SELinuxTypeValid: true, SELinuxPolicyDirOK: true, SELinuxPolicyPkgOK: true,
				SELinuxRelabelPending: true,
			},
			want: "WARN",
		},
		{
			name: "apparmor complain mode is WARN",
			mac:  models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "enforce", AppArmorComplain: 2},
			want: "WARN",
		},
		{
			name: "apparmor denials is WARN",
			mac:  models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "enforce", AppArmorDenials: 3},
			want: "WARN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkKernelSecurity(tt.mac, defaultThresh), tt.want)
		})
	}
}

// ── Workload-aware sysctl tuning ──────────────────────────────────────────────

func TestCheckSysctl(t *testing.T) {
	tests := []struct {
		name string
		s    models.SysctlInfo
		want string
	}{
		{"clean is empty", models.SysctlInfo{}, ""},
		{"somaxconn critically low is CRIT", models.SysctlInfo{NetSomaxconn: 256}, "CRIT"},
		{"somaxconn low is WARN", models.SysctlInfo{NetSomaxconn: 800}, "WARN"},
		{"PID table near full is CRIT", models.SysctlInfo{KernelPIDMax: 1000, PIDCount: 950}, "CRIT"},
		{"PID table high is WARN", models.SysctlInfo{KernelPIDMax: 1000, PIDCount: 850}, "WARN"},
		{"elasticsearch low max_map_count is CRIT", models.SysctlInfo{Workload: "elasticsearch", VMMaxMapCount: 1000}, "CRIT"},
		{"k8s high swappiness is WARN", models.SysctlInfo{Workload: "k8s", VMSwappiness: 30}, "WARN"},
		{"default high swappiness is WARN", models.SysctlInfo{Workload: "", VMSwappiness: 40}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkSysctl(tt.s), tt.want)
		})
	}
}
