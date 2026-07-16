package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/fleet"
)

func TestFleetCheckCategory(t *testing.T) {
	t.Parallel()
	cases := []struct {
		check string
		want  string
	}{
		{"Disk", "storage"},
		{"DRBD", "storage"},
		{"LVM", "storage"},
		{"ZFS", "storage"},
		{"RAID", "storage"},
		{"Memory", "memory"},
		{"Swap", "memory"},
		{"CVE", "patches"},
		{"Packages", "patches"},
		{"Kernel", "patches"},
		{"Hardening", "security"},
		{"TLS", "security"},
		{"Sessions", "security"},
		{"Systemd", "services"},
		{"Services", "services"},
		{"Network", "network"},
		{"DNS", "network"},
		{"Clock", "network"},
		{"CPU", "compute"},
		{"OOM", "compute"},
		{"PostBoot", "compute"},
		{"UnknownCheck", "other"},
	}
	for _, c := range cases {
		t.Run(c.check, func(t *testing.T) {
			t.Parallel()
			if got := fleetCheckCategory(c.check); got != c.want {
				t.Errorf("fleetCheckCategory(%q) = %q, want %q", c.check, got, c.want)
			}
		})
	}
}

func TestWaveRegressionCategory(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want string
	}{
		{"NIC driver", "driver"},
		{"vmware-network-adapter", "driver"},
		{"virtio paravirt", "driver"},
		{"cloud-init firstboot", "cloud-init"},
		{"disk usage", "storage"},
		{"filesystem", "storage"},
		{"systemd unit failed", "services"},
		{"CVE packages", "security"},
		{"ssh key", "security"},
		{"memory usage", "memory"},
		{"OOM killed", "memory"},
		{"something-random", "other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := waveRegressionCategory(c.name); got != c.want {
				t.Errorf("waveRegressionCategory(%q) = %q, want %q", c.name, got, c.want)
			}
		})
	}
}

func TestPluralN(t *testing.T) {
	t.Parallel()
	cases := []struct {
		n, total int
		unit     string
		want     string
	}{
		{1, 1, "host", "The host"},
		{5, 5, "host", "All 5 hosts"},
		{1, 5, "host", "1 host"},
		{3, 5, "VM", "3 VMs"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d/%d", c.n, c.total), func(t *testing.T) {
			t.Parallel()
			if got := pluralN(c.n, c.total, c.unit); got != c.want {
				t.Errorf("pluralN(%d,%d,%q) = %q, want %q", c.n, c.total, c.unit, got, c.want)
			}
		})
	}
}

func TestFleetConsequences_NoIssues(t *testing.T) {
	t.Parallel()
	s := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "OK"},
	})
	if got := fleetConsequences(s); got != nil {
		t.Errorf("expected nil for healthy fleet, got %v", got)
	}
}

func TestFleetConsequences_CritBeforeWarn(t *testing.T) {
	t.Parallel()
	s := fleet.Summarize([]fleet.Result{
		{
			Host: "web01", Reachable: true, Worst: "CRIT", Crit: 1,
			Issues: []fleet.Issue{
				{Check: "Disk", Level: "CRIT", Message: "disk full"},
				{Check: "Memory", Level: "WARN", Message: "swap high"},
			},
		},
	})
	bullets := fleetConsequences(s)
	if len(bullets) == 0 {
		t.Fatal("expected at least one bullet")
	}
	// CRIT storage bullet must come first
	if !strings.Contains(bullets[0], "storage failure") {
		t.Errorf("first bullet should be CRIT storage, got: %q", bullets[0])
	}
}

func TestFleetConsequences_CritSuppressesWarnSameCategory(t *testing.T) {
	t.Parallel()
	// Two issues in the same category (storage): one CRIT one WARN.
	// After dedup, only the CRIT bullet should appear.
	s := fleet.Summarize([]fleet.Result{
		{
			Host: "web01", Reachable: true, Worst: "CRIT", Crit: 1,
			Issues: []fleet.Issue{
				{Check: "Disk", Level: "CRIT", Message: "disk full"},
				{Check: "RAID", Level: "WARN", Message: "degraded"},
			},
		},
	})
	bullets := fleetConsequences(s)
	storageCount := 0
	for _, b := range bullets {
		if strings.Contains(b, "storage") {
			storageCount++
		}
	}
	if storageCount > 1 {
		t.Errorf("CRIT should suppress WARN in same category: got %d storage bullets", storageCount)
	}
}

func TestFleetConsequences_MaxFiveBullets(t *testing.T) {
	t.Parallel()
	checks := []string{"Disk", "Memory", "CVE", "Hardening", "Systemd", "Network", "CPU"}
	issues := make([]fleet.Issue, 0, len(checks))
	for _, ch := range checks {
		issues = append(issues, fleet.Issue{Check: ch, Level: "CRIT", Message: "bad"})
	}
	s := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "CRIT", Crit: len(checks), Issues: issues},
	})
	bullets := fleetConsequences(s)
	if len(bullets) > 5 {
		t.Errorf("expected at most 5 bullets, got %d", len(bullets))
	}
}

func TestWaveConsequences_AllPass(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{Pair: wavePair{"a", "b"}, Verdict: certPass},
	}
	if got := waveConsequences(results); got != nil {
		t.Errorf("expected nil for all-pass wave, got %v", got)
	}
}

func TestWaveConsequences_DriverRegression(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{
			Pair:    wavePair{"vm01", "dst01"},
			Verdict: certFail,
			Regressions: []baseline.DiffEntry{
				{Name: "vmware-network-driver", Before: "OK", After: "WARN", StatusChange: "OK→WARN", Changed: true},
			},
		},
	}
	bullets := waveConsequences(results)
	if len(bullets) == 0 {
		t.Fatal("expected at least one consequence bullet")
	}
	if !strings.Contains(bullets[0], "paravirtual") {
		t.Errorf("driver regression should produce paravirtual bullet, got: %q", bullets[0])
	}
}

func TestWaveConsequences_LoadError(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{Pair: wavePair{"vm01", "dst01"}, Verdict: certFail, Err: fmt.Errorf("bundle not found")},
		{Pair: wavePair{"vm02", "dst02"}, Verdict: certPass},
	}
	bullets := waveConsequences(results)
	if len(bullets) == 0 {
		t.Fatal("expected at least one bullet")
	}
	// load-error should be first
	if !strings.Contains(bullets[0], "bundle load") {
		t.Errorf("load error should be first bullet, got: %q", bullets[0])
	}
}

func TestWaveConsequences_MaxFiveBullets(t *testing.T) {
	t.Parallel()
	regressions := []baseline.DiffEntry{
		{Name: "vmware-nic", Changed: true},
		{Name: "cloud-init", Changed: true},
		{Name: "disk-usage", Changed: true},
		{Name: "systemd-unit", Changed: true},
		{Name: "cve-kernel", Changed: true},
		{Name: "memory-swap", Changed: true},
	}
	results := []waveResult{
		{Pair: wavePair{"src", "dst"}, Verdict: certFail, Regressions: regressions},
	}
	bullets := waveConsequences(results)
	if len(bullets) > 5 {
		t.Errorf("expected at most 5 bullets, got %d", len(bullets))
	}
}
