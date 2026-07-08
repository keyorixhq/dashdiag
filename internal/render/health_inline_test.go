package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// The inline* renderers take interface{} and type-assert to a concrete model.
// On a failed assertion they return "" with no error — so a refactor that breaks
// an assertion (or drops the value-vs-pointer branch) silently blanks a field in
// the health report. These tests guard that class of regression for a
// representative set of renderers:
//   - nil and wrong-type input must return "" (the defensive guard)
//   - valid input in BOTH value and pointer form must return non-empty

type inlineFn = func(interface{}) string

type inlineCase struct {
	fn    inlineFn
	value interface{} // valid input, value form
	ptr   interface{} // same data, pointer form
}

func inlineCases() map[string]inlineCase {
	return map[string]inlineCase{
		"CPULoad":  {inlineCPULoad, models.CPUInfo{UsagePct: 50}, &models.CPUInfo{UsagePct: 50}},
		"Memory":   {inlineMemory, models.MemoryInfo{TotalGB: 16, UsedPct: 50}, &models.MemoryInfo{TotalGB: 16, UsedPct: 50}},
		"Swap":     {inlineSwap, models.SwapInfo{TotalGB: 4, UsedGB: 1}, &models.SwapInfo{TotalGB: 4, UsedGB: 1}},
		"Entropy":  {inlineEntropy, models.EntropyInfo{Available: true, EntropyBits: 256}, &models.EntropyInfo{Available: true, EntropyBits: 256}},
		"FDLimits": {inlineFDLimits, models.FDInfo{MaxCount: 1000, OpenCount: 500, UsedPct: 50}, &models.FDInfo{MaxCount: 1000, OpenCount: 500, UsedPct: 50}},
		"OOM":      {inlineOOM, models.OOMInfo{Available: true, EventsLast24h: 3}, &models.OOMInfo{Available: true, EventsLast24h: 3}},
		"LVM":      {inlineLVM, models.LVMInfo{VGs: []models.LVMVG{{}}}, &models.LVMInfo{VGs: []models.LVMVG{{}}}},
		"Sessions": {inlineSessions, models.SessionsInfo{TotalCount: 2}, &models.SessionsInfo{TotalCount: 2}},
		"IPMI":     {inlineIPMI, models.IPMIInfo{Available: true}, &models.IPMIInfo{Available: true}},
	}
}

func TestInlineNilAndWrongTypeReturnEmpty(t *testing.T) {
	type wrong struct{ X int }
	for name, c := range inlineCases() {
		if got := c.fn(nil); got != "" {
			t.Errorf("%s(nil) = %q, want empty", name, got)
		}
		if got := c.fn(wrong{1}); got != "" {
			t.Errorf("%s(wrong-type) = %q, want empty (silent type-assertion guard)", name, got)
		}
	}
}

func TestInlineValidInputNonEmpty(t *testing.T) {
	for name, c := range inlineCases() {
		if got := c.fn(c.value); got == "" {
			t.Errorf("%s(value form) returned empty for valid input", name)
		}
		if got := c.fn(c.ptr); got == "" {
			t.Errorf("%s(pointer form) returned empty for valid input", name)
		}
	}
}

// inlineMemory does arithmetic on the populated struct — pin its exact output as
// a representative formatting regression guard.
func TestInlineMemoryFormat(t *testing.T) {
	got := inlineMemory(models.MemoryInfo{TotalGB: 16, UsedPct: 50})
	if got != "8.0/16 GB (50%)" {
		t.Errorf("inlineMemory = %q, want %q", got, "8.0/16 GB (50%)")
	}
}

// A "0 updates" result must NOT render "up to date" when the update metadata is
// stale/absent — that's a false-OK. The heuristic surfaces the "cannot confirm"
// reason instead; the inline text must yield to it.
func TestInlinePackagesStaleNotUpToDate(t *testing.T) {
	stale := models.PackagesInfo{Checked: true, SecurityUpdates: 0, Status: "stale-metadata", PackageManager: "apt"}
	if got := inlinePackages(stale); got == "up to date" {
		t.Errorf("stale metadata: inlinePackages = %q, must not claim 'up to date'", got)
	}
	fresh := models.PackagesInfo{Checked: true, SecurityUpdates: 0, PackageManager: "apt"}
	if got := inlinePackages(fresh); got != "up to date" {
		t.Errorf("fresh/clean: inlinePackages = %q, want 'up to date'", got)
	}
}

// BUG-098: query-failed (scan timed out / errored) and no-security-repo must not
// render "up to date" either — Checked is set true at collector init before the
// scan even runs, so these two statuses previously fell through the same
// blacklist gap stale-metadata was fixed for above, reading as a false "up to
// date" summary on a scan that timed out (found on Oracle Linux, cold dnf cache).
func TestInlinePackagesQueryFailedNotUpToDate(t *testing.T) {
	cases := []models.PackagesInfo{
		{Checked: true, SecurityUpdates: 0, Status: "query-failed", PackageManager: "dnf"},
		{Checked: true, SecurityUpdates: 0, Status: "no-security-repo", PackageManager: "dnf"},
	}
	for _, p := range cases {
		if got := inlinePackages(p); got == "up to date" {
			t.Errorf("status %q: inlinePackages = %q, must not claim 'up to date'", p.Status, got)
		}
	}
}

// A drive detected via sysfs but with no SMART log read (no nvme-cli, common on
// minimal cloud/ARM images) must NOT be rendered "healthy" — that's a false-OK.
func TestInlineDrivesSmartUnread(t *testing.T) {
	unread := models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "/dev/nvme0", SmartRead: false}}}
	if got := inlineDrives(unread); got != "/dev/nvme0  detected (SMART not read)" {
		t.Errorf("unread drive: inlineDrives = %q, want SMART-not-read text", got)
	}
	read := models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "/dev/nvme0", SmartRead: true}}}
	if got := inlineDrives(read); got != "/dev/nvme0  healthy" {
		t.Errorf("verified drive: inlineDrives = %q, want healthy", got)
	}
	mixed := models.NVMeInfo{Devices: []models.NVMeDevice{
		{Name: "/dev/nvme0", SmartRead: true}, {Name: "/dev/nvme1", SmartRead: false},
	}}
	if got := inlineDrives(mixed); got != "2 drives, 1 SMART not read" {
		t.Errorf("mixed drives: inlineDrives = %q, want count with unread note", got)
	}

	// SATA drives whose smartctl errored (non-root — validated on pve01) must NOT
	// be tallied as "healthy"; counting only NVMe here was the false-OK.
	sataErrored := models.NVMeInfo{SATADevices: []models.SATADevice{
		{Name: "/dev/sda", SmartRead: false, Error: "smartctl failed"},
		{Name: "/dev/sdb", SmartRead: false, Error: "smartctl failed"},
	}}
	if got := inlineDrives(sataErrored); got != "2 drives, 2 SMART not read" {
		t.Errorf("non-root SATA: inlineDrives = %q, want all-unread, not healthy", got)
	}
	singleSATAErr := models.NVMeInfo{SATADevices: []models.SATADevice{
		{Name: "/dev/sda", SmartRead: false, Error: "smartctl failed"},
	}}
	if got := inlineDrives(singleSATAErr); got != "/dev/sda  detected (SMART not read)" {
		t.Errorf("single errored SATA: inlineDrives = %q, want SMART-not-read text", got)
	}
	// A genuinely verified SATA drive still renders healthy.
	sataOK := models.NVMeInfo{SATADevices: []models.SATADevice{
		{Name: "/dev/sda", SmartRead: true, SmartOK: true},
	}}
	if got := inlineDrives(sataOK); got != "/dev/sda  healthy" {
		t.Errorf("verified SATA: inlineDrives = %q, want healthy", got)
	}

	// AWS EBS / virtual NVMe: SMART "read" but all sentinels (0K temp, all-zero) —
	// must NOT render "healthy" (validated live on a Graviton2 t4g.small).
	ebs := models.NVMeInfo{Devices: []models.NVMeDevice{
		{Name: "/dev/nvme0", SmartRead: true, TempC: -273},
		{Name: "/dev/nvme1", SmartRead: true, TempC: -273},
	}}
	if got := inlineDrives(ebs); got != "2 drives, 2 SMART not read" {
		t.Errorf("EBS sentinel NVMe: inlineDrives = %q, want all-unread, not healthy", got)
	}
	// A real NVMe with a real temp still renders healthy.
	realNVMe := models.NVMeInfo{Devices: []models.NVMeDevice{
		{Name: "/dev/nvme0", SmartRead: true, TempC: 35},
	}}
	if got := inlineDrives(realNVMe); got != "/dev/nvme0  healthy" {
		t.Errorf("real NVMe: inlineDrives = %q, want healthy", got)
	}
}

// Sub-GB totals (small containers / minimal VMs) used to floor to "0 GB" under
// %.0f, rendering a broken-looking "0.1/0 GB". Below 1 GB we switch to MB.
func TestInlineMemorySubGB(t *testing.T) {
	got := inlineMemory(models.MemoryInfo{TotalGB: 0.5, UsedPct: 12})
	if got != "61/512 MB (12%)" {
		t.Errorf("inlineMemory = %q, want %q", got, "61/512 MB (12%)")
	}
}

// TestCPUDisplayPct covers the observer-effect reconciliation: the grid prefers
// the instantaneous user+sys% (htop match) but falls back to the load-derived
// figure when a light box reads implausibly high (dsd's own collection noise).
func TestCPUDisplayPct(t *testing.T) {
	cases := []struct {
		name        string
		usage, load float64
		want        float64
	}{
		{"idle box, contaminated reading → show load", 70, 0, 0},
		{"truly idle, mild contamination → show load", 35, 0, 0},
		{"normal light box, usage≈load → htop match", 25, 25, 25},
		{"boundary gap (==25) stays htop match", 40, 15, 40},
		{"busy box → instantaneous (htop match)", 81, 80, 81},
		{"I/O-bound: high load, low CPU → show low usage", 10, 90, 10},
		{"usage unavailable → fall back to load", 0, 12, 12},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cpuDisplayPct(&models.CPUInfo{UsagePct: tc.usage, LoadPct: tc.load})
			if got != tc.want {
				t.Errorf("cpuDisplayPct(usage=%v, load=%v) = %v, want %v", tc.usage, tc.load, got, tc.want)
			}
		})
	}
}
