package analysis

import (
	"fmt"
	"math"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyFile is the YAML structure for a dsd policy file.
// Only fields explicitly set in the file override defaults —
// zero values are ignored (use explicit non-zero to override).
//
// Example policy file:
//
//	# dsd policy — CI gate thresholds
//	ram_warn_pct: 70
//	ram_crit_pct: 90
//	disk_warn_pct: 75
//	disk_crit_pct: 85
//	deny:
//	  - WARN    # fail CI on any WARN or CRIT
type PolicyFile struct {
	// Memory
	RAMWarnPct  float64 `yaml:"ram_warn_pct"`
	RAMCritPct  float64 `yaml:"ram_crit_pct"`
	SlabWarnPct float64 `yaml:"slab_warn_pct"`

	// CPU
	CPULoadWarnMultiplier float64 `yaml:"cpu_load_warn_multiplier"`
	CPULoadCritMultiplier float64 `yaml:"cpu_load_crit_multiplier"`

	// Disk
	DiskWarnPct float64 `yaml:"disk_warn_pct"`
	DiskCritPct float64 `yaml:"disk_crit_pct"`

	// Swap
	SwapWarnPct      float64 `yaml:"swap_warn_pct"`
	SwapCritPct      float64 `yaml:"swap_crit_pct"`
	SwapActivityWarn float64 `yaml:"swap_activity_warn"`
	SwapActivityCrit float64 `yaml:"swap_activity_crit"`

	// IO
	IOAwaitWarnMs float64 `yaml:"io_await_warn_ms"`
	IOAwaitCritMs float64 `yaml:"io_await_crit_ms"`
	IOUtilWarnPct float64 `yaml:"io_util_warn_pct"`
	IOUtilCritPct float64 `yaml:"io_util_crit_pct"`

	// NTP
	NTPOffsetWarnMs float64 `yaml:"ntp_offset_warn_ms"`
	NTPOffsetCritMs float64 `yaml:"ntp_offset_crit_ms"`

	// File descriptors
	FDSystemWarnPct float64 `yaml:"fd_system_warn_pct"`
	FDSystemCritPct float64 `yaml:"fd_system_crit_pct"`

	// Processes
	ZombieWarnCount int `yaml:"zombie_warn_count"`
	HungDStateCrit  int `yaml:"hung_d_state_crit"`

	// Deny — which levels cause non-zero exit: ["WARN", "CRIT"] or ["CRIT"]
	// Default (empty): exit non-zero on CRIT only.
	Deny []string `yaml:"deny"`
}

// LoadPolicy parses a policy YAML file and returns the PolicyFile.
func LoadPolicy(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- user-provided path, expected
	if err != nil {
		return nil, fmt.Errorf("cannot read policy file %q: %w", path, err)
	}
	var p PolicyFile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("cannot parse policy file %q: %w", path, err)
	}
	if err := validatePolicy(&p); err != nil {
		return nil, fmt.Errorf("policy file %q: %w", path, err)
	}
	return &p, nil
}

// pctField names a percentage-typed PolicyFile field for range validation.
type pctField struct {
	name string
	val  float64
}

// validatePolicy rejects threshold values that would silently defeat the CI
// health gate: a percentage above 100 (or the YAML 1.1 literal ".inf", which
// gopkg.in/yaml.v3 accepts as +Inf) makes the corresponding WARN/CRIT
// classification permanently unreachable, since the underlying metric can
// never reach it. It also validates Deny entries are recognized level names
// (case-insensitive) and normalizes them to upper-case in place, so a typo'd
// or wrong-case deny list ("warn" instead of "WARN") is caught as a config
// error instead of silently behaving as "deny nothing".
func validatePolicy(p *PolicyFile) error {
	pcts := []pctField{
		{"ram_warn_pct", p.RAMWarnPct}, {"ram_crit_pct", p.RAMCritPct},
		{"slab_warn_pct", p.SlabWarnPct},
		{"disk_warn_pct", p.DiskWarnPct}, {"disk_crit_pct", p.DiskCritPct},
		{"swap_warn_pct", p.SwapWarnPct}, {"swap_crit_pct", p.SwapCritPct},
		{"io_util_warn_pct", p.IOUtilWarnPct}, {"io_util_crit_pct", p.IOUtilCritPct},
		{"fd_system_warn_pct", p.FDSystemWarnPct}, {"fd_system_crit_pct", p.FDSystemCritPct},
	}
	for _, f := range pcts {
		if f.val == 0 {
			continue // unset — defaults apply
		}
		if math.IsInf(f.val, 0) || math.IsNaN(f.val) || f.val < 0 || f.val > 100 {
			return fmt.Errorf("%s: %v is not a valid percentage (must be > 0 and <= 100)", f.name, f.val)
		}
	}

	// Non-percentage numeric fields must still be finite and non-negative —
	// ".inf"/negative values are nonsensical thresholds that never trip.
	others := []pctField{
		{"cpu_load_warn_multiplier", p.CPULoadWarnMultiplier}, {"cpu_load_crit_multiplier", p.CPULoadCritMultiplier},
		{"swap_activity_warn", p.SwapActivityWarn}, {"swap_activity_crit", p.SwapActivityCrit},
		{"io_await_warn_ms", p.IOAwaitWarnMs}, {"io_await_crit_ms", p.IOAwaitCritMs},
		{"ntp_offset_warn_ms", p.NTPOffsetWarnMs}, {"ntp_offset_crit_ms", p.NTPOffsetCritMs},
	}
	for _, f := range others {
		if f.val == 0 {
			continue
		}
		if math.IsInf(f.val, 0) || math.IsNaN(f.val) || f.val < 0 {
			return fmt.Errorf("%s: %v is not a valid threshold (must be finite and >= 0)", f.name, f.val)
		}
	}

	for i, d := range p.Deny {
		u := strings.ToUpper(strings.TrimSpace(d))
		if u != "WARN" && u != "CRIT" {
			return fmt.Errorf("deny[%d]: %q is not a recognized level (must be WARN or CRIT)", i, d)
		}
		p.Deny[i] = u
	}

	return nil
}

// ApplyPolicy overrides threshold fields from a policy file.
// Only non-zero values in the policy override the defaults.
func ApplyPolicy(t Thresholds, p *PolicyFile) Thresholds {
	if p == nil {
		return t
	}
	if p.RAMWarnPct > 0 {
		t.RAMWarnPct = p.RAMWarnPct
	}
	if p.RAMCritPct > 0 {
		t.RAMCritPct = p.RAMCritPct
	}
	if p.SlabWarnPct > 0 {
		t.SlabWarnPct = p.SlabWarnPct
	}
	if p.CPULoadWarnMultiplier > 0 {
		t.CPULoadWarnMultiplier = p.CPULoadWarnMultiplier
	}
	if p.CPULoadCritMultiplier > 0 {
		t.CPULoadCritMultiplier = p.CPULoadCritMultiplier
	}
	if p.DiskWarnPct > 0 {
		t.DiskWarnPct = p.DiskWarnPct
	}
	if p.DiskCritPct > 0 {
		t.DiskCritPct = p.DiskCritPct
	}
	if p.SwapWarnPct > 0 {
		t.SwapWarnPct = p.SwapWarnPct
	}
	if p.SwapCritPct > 0 {
		t.SwapCritPct = p.SwapCritPct
	}
	if p.SwapActivityWarn > 0 {
		t.SwapActivityWarn = p.SwapActivityWarn
	}
	if p.SwapActivityCrit > 0 {
		t.SwapActivityCrit = p.SwapActivityCrit
	}
	if p.IOAwaitWarnMs > 0 {
		t.IOAwaitWarnMsSSD = p.IOAwaitWarnMs
	}
	if p.IOAwaitCritMs > 0 {
		t.IOAwaitCritMsSSD = p.IOAwaitCritMs
	}
	if p.IOUtilWarnPct > 0 {
		t.IOUtilWarnPctSSD = p.IOUtilWarnPct
	}
	if p.IOUtilCritPct > 0 {
		t.IOUtilCritPctSSD = p.IOUtilCritPct
	}
	if p.NTPOffsetWarnMs > 0 {
		t.NTPOffsetWarnMs = p.NTPOffsetWarnMs
	}
	if p.NTPOffsetCritMs > 0 {
		t.NTPOffsetCritMs = p.NTPOffsetCritMs
	}
	if p.FDSystemWarnPct > 0 {
		t.FDSystemWarnPct = p.FDSystemWarnPct
	}
	if p.FDSystemCritPct > 0 {
		t.FDSystemCritPct = p.FDSystemCritPct
	}
	if p.ZombieWarnCount > 0 {
		t.ZombieWarnCount = p.ZombieWarnCount
	}
	if p.HungDStateCrit > 0 {
		t.HungDStateCrit = p.HungDStateCrit
	}
	return t
}

// PolicyDeniesLevel returns true when the policy's deny list includes the given level.
// An empty deny list defaults to denying CRIT only.
func PolicyDeniesLevel(p *PolicyFile, level string) bool {
	if p == nil || len(p.Deny) == 0 {
		return level == "CRIT"
	}
	return slices.Contains(p.Deny, level)
}

// PolicyInitTemplate returns a starter policy YAML with comments.
// Intended for: dsd policy init > .dsd-policy.yaml
const PolicyInitTemplate = `# DashDiag policy file — CI gate thresholds
# Place at: .dsd-policy.yaml (project root) or specify with --policy PATH
# Usage:    dsd health --policy .dsd-policy.yaml
#
# Only fields listed here override defaults. Remove or comment out
# any field to use the DashDiag default value.
#
# Exit codes: 0 = all OK, 1 = WARN, 2 = CRIT
# deny controls which levels cause non-zero exit:
deny:
  - CRIT         # fail CI on any CRIT (default)
  # - WARN       # uncomment to also fail on any WARN

# Memory thresholds (%)
ram_warn_pct: 80
ram_crit_pct: 95

# CPU load as multiplier of core count (0.9 = 90% of cores)
cpu_load_warn_multiplier: 0.7
cpu_load_crit_multiplier: 0.9

# Disk usage thresholds (%)
disk_warn_pct: 80
disk_crit_pct: 90

# Swap usage thresholds (%)
swap_warn_pct: 20
swap_crit_pct: 60

# IO await latency (ms) — tune per storage type
io_await_warn_ms: 2
io_await_crit_ms: 10

# NTP offset thresholds (ms)
ntp_offset_warn_ms: 100
ntp_offset_crit_ms: 500
`
