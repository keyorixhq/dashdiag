package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/fleet"
)

const (
	catLoadError = "load-error"
	catCloudInit = "cloud-init"
)

// fleetConsequences derives a short list of business-consequence bullets from a
// fleet.Summary, ordered by severity (CRIT first) then affected-host count. Each
// bullet names a consequence category in plain language — intended for a
// non-technical MSP client reading the HTML report, not the operator.
//
// Returns nil when there are no issues (all-healthy fleet), so callers can gate
// the "What This Means" section on a nil/empty check.
func fleetConsequences(s fleet.Summary) []string {
	if len(s.Issues) == 0 {
		return nil
	}
	reachable := s.Total - s.Counts.Unreachable

	type key struct{ cat, level string }
	hostSets := make(map[key]map[string]struct{})
	for _, g := range s.Issues {
		k := key{cat: fleetCheckCategory(g.Check), level: g.Level}
		if hostSets[k] == nil {
			hostSets[k] = make(map[string]struct{})
		}
		for _, h := range g.Hosts {
			hostSets[k][h] = struct{}{}
		}
	}

	// Deduplicate: if a category has both CRIT and WARN entries, keep only CRIT.
	for k, hosts := range hostSets {
		if k.level == "CRIT" {
			warnKey := key{cat: k.cat, level: "WARN"}
			delete(hostSets, warnKey)
			_ = hosts
		}
	}

	type entry struct {
		cat, level string
		count      int
	}
	entries := make([]entry, 0, len(hostSets))
	for k, hosts := range hostSets {
		entries = append(entries, entry{cat: k.cat, level: k.level, count: len(hosts)})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].level != entries[j].level {
			return entries[i].level == "CRIT"
		}
		return entries[i].count > entries[j].count
	})

	const maxBullets = 5
	out := make([]string, 0, maxBullets)
	for _, e := range entries {
		if len(out) >= maxBullets {
			break
		}
		out = append(out, fleetConsequenceLine(e.cat, e.level, e.count, reachable))
	}
	return out
}

// fleetCheckCategory maps a health check name to a consequence category.
func fleetCheckCategory(check string) string {
	switch {
	case hasAnyPrefix(check, "Disk", "RAID", "DRBD", "Multipath", "Ceph", "LVM",
		"ZFS", "Root FS", "Drives", "HBA", "IO", "Fstab"):
		return "storage"
	case hasAnyPrefix(check, "Memory", "Swap", "Pressure", "NUMA", "HugePages"):
		return "memory"
	case hasAnyPrefix(check, "CVE", "Packages", "Kernel", "LivePatch", "Ksplice"):
		return "patches"
	case hasAnyPrefix(check, "Hardening", "TLS", "Sessions", "KernelSec",
		"Security", "MTE"):
		return "security"
	case hasAnyPrefix(check, "Systemd", "Services", "ServiceRestart", "Launchd",
		"Cron", "DBus"):
		return "services"
	case hasAnyPrefix(check, "Network", "DNS", "Clock", "VLAN", "Entropy"):
		return "network"
	case hasAnyPrefix(check, "CPU", "Processes", "OOM", "Cgroup", "Logs",
		"PostBoot", "Pressure"):
		return "compute"
	default:
		return "other"
	}
}

func fleetConsequenceLine(cat, level string, n, total int) string {
	hosts := pluralN(n, total, "host")
	switch cat {
	case "storage":
		if level == "CRIT" {
			return fmt.Sprintf("%s face immediate storage failure risk — data loss or outage possible", hosts)
		}
		return fmt.Sprintf("%s have storage issues requiring attention", hosts)
	case "memory":
		if level == "CRIT" {
			return fmt.Sprintf("%s are under critical memory pressure — crashes or slowdowns likely", hosts)
		}
		return fmt.Sprintf("%s have elevated memory pressure", hosts)
	case "patches":
		if level == "CRIT" {
			return fmt.Sprintf("%s have critical unpatched vulnerabilities (CVSS ≥9.0 or actively exploited)", hosts)
		}
		return fmt.Sprintf("%s have pending security patches", hosts)
	case "security":
		return fmt.Sprintf("%s have security hardening gaps", hosts)
	case "services":
		if level == "CRIT" {
			return fmt.Sprintf("%s have failed or crashing services", hosts)
		}
		return fmt.Sprintf("%s have service reliability issues", hosts)
	case "network":
		if level == "CRIT" {
			return fmt.Sprintf("%s have network connectivity faults", hosts)
		}
		return fmt.Sprintf("%s have network configuration issues", hosts)
	case "compute":
		if level == "CRIT" {
			return fmt.Sprintf("%s have critical compute resource exhaustion", hosts)
		}
		return fmt.Sprintf("%s have compute resource pressure", hosts)
	default:
		if level == "CRIT" {
			return fmt.Sprintf("%s have critical issues requiring immediate attention", hosts)
		}
		return fmt.Sprintf("%s have issues requiring review", hosts)
	}
}

// waveConsequences derives business-consequence bullets from a wave certify run.
// Returns nil when all pairs passed (no consequences to surface).
func waveConsequences(results []waveResult) []string {
	if waveWorstVerdict(results) == certPass {
		return nil
	}

	type catKey = string
	pairsByCategory := make(map[catKey]int)
	total := len(results)

	for _, r := range results {
		if r.Verdict == certPass {
			continue
		}
		seen := make(map[string]struct{})
		if r.Err != nil {
			seen[catLoadError] = struct{}{}
		}
		for _, reg := range r.Regressions {
			cat := waveRegressionCategory(reg.Name)
			seen[cat] = struct{}{}
		}
		for cat := range seen {
			pairsByCategory[cat]++
		}
	}

	type entry struct {
		cat   string
		count int
	}
	entries := make([]entry, 0, len(pairsByCategory))
	for cat, n := range pairsByCategory {
		entries = append(entries, entry{cat: cat, count: n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].cat == catLoadError {
			return true
		}
		return entries[i].count > entries[j].count
	})

	const maxBullets = 5
	out := make([]string, 0, maxBullets)
	for _, e := range entries {
		if len(out) >= maxBullets {
			break
		}
		out = append(out, waveConsequenceLine(e.cat, e.count, total))
	}
	return out
}

// waveRegressionCategory maps a certify regression name to a consequence category.
func waveRegressionCategory(name string) string {
	lower := strings.ToLower(name)
	switch {
	case hasAnySubstr(lower, "driver", "nic", "vmware", "network", "vnic", "ena",
		"virtio", "paravirt"):
		return "driver"
	case hasAnySubstr(lower, "cloudinit", catCloudInit, "cloud_init", "firstboot",
		"first-boot", "first_boot"):
		return catCloudInit
	case hasAnySubstr(lower, "disk", "storage", "filesystem", "fs", "mount", "lvm",
		"raid", "zfs"):
		return "storage"
	case hasAnySubstr(lower, "service", "systemd", "unit", "launchd", "cron"):
		return "services"
	case hasAnySubstr(lower, "security", "hardening", "cve", "packages", "tls",
		"ssh", "kernel"):
		return "security"
	case hasAnySubstr(lower, "memory", "swap", "oom", "pressure"):
		return "memory"
	default:
		return "other"
	}
}

func waveConsequenceLine(cat string, n, total int) string {
	vms := pluralN(n, total, "VM")
	switch cat {
	case "driver":
		return fmt.Sprintf("%s landed on emulated network drivers — paravirtual performance not restored", vms)
	case catCloudInit:
		return fmt.Sprintf("%s did not complete first-boot provisioning on the destination", vms)
	case "storage":
		return fmt.Sprintf("%s have storage or filesystem regressions post-migration", vms)
	case "services":
		return fmt.Sprintf("%s have service failures on the destination host", vms)
	case "security":
		return fmt.Sprintf("%s have security posture regressions that must be remediated", vms)
	case "memory":
		return fmt.Sprintf("%s have memory or swap regressions post-migration", vms)
	case catLoadError:
		return fmt.Sprintf("%s could not be certified — bundle load or replay error", vms)
	default:
		return fmt.Sprintf("%s have regressions requiring remediation", vms)
	}
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func hasAnySubstr(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// pluralN formats "N of T unit(s)" with natural-language shortcuts.
func pluralN(n, total int, unit string) string {
	switch {
	case n == total && total == 1:
		return "The " + unit
	case n == total:
		return fmt.Sprintf("All %d %ss", total, unit)
	case n == 1:
		return fmt.Sprintf("1 %s", unit)
	default:
		return fmt.Sprintf("%d %ss", n, unit)
	}
}
