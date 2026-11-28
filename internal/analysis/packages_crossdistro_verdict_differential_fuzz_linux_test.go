//go:build linux

package analysis

// FuzzPackagesCrossDistroVerdictDifferential is a CROSS-DISTRIBUTION *verdict*
// differential (backlog DD-CROSSDISTRO-1). It closes the loop the existing
// collector-field differential leaves open: the same logical set of pending
// security updates, rendered in FOUR package-manager dialects (dnf, apt, zypper,
// AND tdnf), driven through the REAL exported collector AND the REAL analysis
// (`collectors.PackagesCollector.Collect` → `ApplyThresholds`), must yield the
// same security-update VERDICT CLASS and the same NUMBER of security-update
// insights — not just the same raw field counts.
//
// How it differs from the sibling coverage (deliberately non-duplicative):
//
//   - `collectors.FuzzSecurityUpdatesCrossDistroDifferential`
//     (packages_crossdistro_differential_fuzz_linux_test.go) compares COLLECTOR
//     FIELDS (SecurityUpdates/Critical/Important) for dnf/apt/zypper only. It
//     stops at the collector and EXCLUDES tdnf (tdnf cannot be driven from
//     `package collectors` through analysis because analysis imports collectors —
//     an import cycle; hence that test never reaches the verdict layer either).
//   - This target runs in `package analysis`, so it can call BOTH the exported
//     `collectors.PackagesCollector.Collect` (no cycle: collectors does not
//     import analysis, verified) AND `ApplyThresholds`. It therefore (a) ADDS
//     tdnf to the cross-distro comparison and (b) ADDS the analysis-layer
//     verdict-class / insight-count oracles.
//
// Distro selection is driven exactly as a real host selects one: the replay
// bundle answers only the chosen manager's `<tool> --version`, so the REAL
// `detectPackageManager` (packages_linux.go:138-153) picks that manager and the
// REAL `PackagesCollector.Collect` dispatches to the real collect<Mgr>. There is
// NO second parser and NO hand-written expected verdict — the oracle is agreement
// between four independent production parsers + the one production analyzer fed
// equivalent inputs. A divergence is a real verdict-integrity bug: dashdiag
// reporting a different security-update verdict on Photon/openSUSE than it would
// for the identical logical state on Debian/Fedora.
//
// ABSTRACT FACT SET (the common denominator all four dialects can express):
// N pending SECURITY updates, each of a NON-CRITICAL severity class
// (Important / Moderate / Low). Severity is varied among the non-critical tiers
// to exercise each parser's severity branch, but CRITICAL is excluded BY
// CONSTRUCTION — see "excluded facts" below.
//
// WRITERS (each modelled on the real fixture/parser it feeds, cited):
//   - renderDNF4  → DNF4 tabular advisory list, parsed at packages_linux.go:364-399
//     ("ADVISORY SEVERITY/Sec. PACKAGE").
//   - renderAPT   → `apt-get -s upgrade` "Inst" lines, parsed at :507-560; the
//     "-security" suite token is what collectAPT counts (:513-517). The trailing
//     "N upgraded …" summary mirrors real apt output so the N==0 case does NOT
//     trip collectAPT's "no security updates found" query-failed branch (:522).
//   - renderZypper→ `zypper list-patches` pipe table, parsed at :758-795
//     (Status col == "needed", Severity col drives Important).
//   - renderTDNF  → `tdnf -j updateinfo list --security` JSON, parsed by
//     parseTDNFUpdateInfoJSON (cve_linux.go:1466), modelled independently on the
//     captured shape in cve_tdnf_linux_test.go:13 (tdnfUpdateInfoJSONFixture:
//     Type/UpdateID/Packages, one object per package).
//
// ORACLES (equalities that must hold for any correct implementation; no
// "must be healthy" direction, so no false positives on correct code):
//
//   - O1 COUNT (4-way field): SecurityUpdates agree across dnf/apt/zypper/tdnf.
//     The primary oracle is cross-distro EQUALITY; a vacuity guard additionally
//     pins dnf to N so 0==0==0==0 cannot pass trivially. This extends the
//     existing 3-way field oracle to tdnf.
//   - O2 VERDICT CLASS (4-way analysis): the security-update verdict class
//     (worst level among the security-update insights, or "none") agrees across
//     all four. For a non-critical set this must be WARN when N>0 and "none"
//     when N==0 — asserted as the non-vacuity guard.
//   - O3 INSIGHT COUNT (4-way analysis): the number of security-update insights
//     agrees across all four (exactly 1 when N>0, 0 when N==0).
//
// EXCLUDED FACTS (one format cannot express them, so excluded by construction
// and listed — per the task's honesty requirement):
//
//   - CRITICAL severity. apt and tdnf publish NO per-advisory CVSS, so
//     securityUpdateInsight (heuristics_packages.go:206-246) folds EVERY apt/tdnf
//     security update to WARN, while dnf/zypper escalate a Critical advisory to
//     CRIT. A critical update is therefore an EXPECTED verdict DIFFERENCE across
//     distros, not a bug — so the abstract set is restricted to non-critical
//     severities. (The dnf/zypper Critical→CRIT path and apt's critical-package
//     counting remain owned by the field-level 3-way differential.)
//   - DB-health and stale-metadata insights. These are DIFFERENT facts (package
//     DB corruption; metadata freshness) and depend on host probes the replay
//     seam does not fully intercept (`lookPath`). They are SEEDED CLEAN and
//     EXCLUDED from the oracle scope (the "security update" message predicate),
//     so they can neither mask nor manufacture a divergence.
//
// What this oracle does NOT verify (per the task's honesty requirement):
//   - Sub-threshold miscounts that do not change the verdict class or insight
//     count (e.g. 3 vs 4 non-critical updates — both WARN, both one insight): O2/O3
//     are blind to those; O1 (and the field-level 3-way differential) own them.
//   - Critical-severity verdicts (excluded above).
//   - Malformed / hostile tool output — this harness feeds well-formed dialect;
//     the per-parser replay fuzzers own that surface.
//   - Real tool-output DRIFT between tool versions, LOCALE, and text ENCODINGS:
//     the writers emit one canonical byte shape per dialect (C/UTF-8), so a future
//     locale- or version-specific format change is out of scope here.
//   - tdnf's text-format fallback and its JSON-vs-text agreement (owned by
//     collectors.FuzzTDNFUpdateInfoJSONTextDifferential); this target renders
//     tdnf's canonical JSON only.
//   - Exact insight MESSAGE text / hints; package-DB health; ESM accounting.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/fuzzutil"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// crossDistroVerdictWorkCeiling is a loose HANG/blow-up backstop, not a tight
// perf bound: driving four collectors + the analyzer over <=96 recorded lines is
// milliseconds. 30s mirrors the sibling crossDistroWorkCeiling — loose enough that
// a descheduled worker on the shared host never flakes, tight enough that a true
// super-linear blow-up over an in-memory bundle is unambiguous.
const crossDistroVerdictWorkCeiling = 30 * time.Second

// nonCritClass is a non-critical severity tier. Rendered into each dialect's own
// spelling; CRITICAL is intentionally absent (see the file header's excluded facts).
type nonCritClass uint8

const (
	clsImportant nonCritClass = iota
	clsModerate
	clsLow
	nonCritClassCount
)

// classesFromBytes maps each fuzz byte to one logical non-critical update,
// capping N so the pipeline stays bounded regardless of input size.
func classesFromBytes(raw []byte) []nonCritClass {
	const maxUpdates = 96
	if len(raw) > maxUpdates {
		raw = raw[:maxUpdates]
	}
	out := make([]nonCritClass, 0, len(raw))
	for _, b := range raw {
		out = append(out, nonCritClass(b%uint8(nonCritClassCount)))
	}
	return out
}

// --- writers (one canonical byte shape per dialect; cited in the file header) ---

func dnfLabel(c nonCritClass) string {
	switch c {
	case clsImportant:
		return "Important"
	case clsModerate:
		return "Moderate"
	default:
		return "Low"
	}
}

func renderDNF4(classes []nonCritClass) string {
	var b strings.Builder
	for i, c := range classes {
		fmt.Fprintf(&b, "RHSA-2024:%04d %s/Sec. pkg%d-1.0.x86_64\n", i, dnfLabel(c), i)
	}
	return b.String()
}

func renderAPT(classes []nonCritClass) string {
	var b strings.Builder
	for i := range classes {
		// "pkgplainN" is deliberately NOT in collectAPT's criticalPkgs set
		// (packages_linux.go:494-504), so every line classifies non-critical.
		fmt.Fprintf(&b, "Inst pkgplain%d [1.0-%d] (1.1-%d Debian-Security:stable/updates [amd64])\n", i, i, i)
	}
	// Real apt summary trailer; its "N upgraded" token keeps collectAPT's
	// "0 updates → query-failed" guard from firing on the empty set (:522).
	fmt.Fprintf(&b, "%d upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", len(classes))
	return b.String()
}

func zypperSeverity(c nonCritClass) string {
	switch c {
	case clsImportant:
		return "important"
	case clsModerate:
		return "moderate"
	default:
		return "low"
	}
}

func renderZypper(classes []nonCritClass) string {
	var b strings.Builder
	b.WriteString("Repository | Name | Category | Severity | Interactive | Status | Summary\n")
	b.WriteString("-----------+------+----------+----------+-------------+--------+--------\n")
	for i, c := range classes {
		fmt.Fprintf(&b, "update-repo | patch-%d | security | %s | --- | needed | fix-%d\n", i, zypperSeverity(c), i)
	}
	return b.String()
}

// renderTDNF renders the abstract set to `tdnf -j updateinfo list --security`
// JSON — one object per logical update (Photon emits one entry per package;
// collectTDNF counts one SecurityUpdates per entry). tdnf has no CVSS, so the
// severity class is not expressible here: every entry folds to Important, which
// is why tdnf participates only in the NON-CRITICAL oracle.
func renderTDNF(classes []nonCritClass) string {
	var b strings.Builder
	b.WriteString("[")
	for i := range classes {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-%04d","Packages":["pkg%d-1.0.ph5.x86_64.rpm"]}`, i, i)
	}
	b.WriteString("]")
	return b.String()
}

// --- replay-bundle seeds (steer detection, seed DB-health clean, seed query) ---

// seedRPMDBHealthy makes rpmDBHealth (dnf/zypper/tdnf) read a clean, present
// rpmdb so DBHealthChecked=true and no DB-health insight is emitted. lookPath
// routes through the source seam (fsaccess.go:30), so rpm "presence" is seeded
// rather than depending on the replaying host actually having rpm.
func seedRPMDBHealthy(b *source.Bundle) {
	b.PutCached("lookpath/rpm", []byte("/usr/bin/rpm"))
	b.PutCmd("rpm", []string{"-q", "rpm"}, "rpm-4.18.0-1.x86_64\n", 0)
}

func bundleDNF(out string) *source.Bundle {
	b := source.NewBundle()
	b.PutCmd("dnf", []string{"--version"}, "dnf 4.18.0\n", 0) // detection picks dnf (zypper --version unseeded → skipped)
	seedRPMDBHealthy(b)
	b.PutCmd("dnf", []string{"--cacheonly", "repolist", "--enabled", "-q"}, "baseos\nappstream\n", 0) // dnfHasUpdateRepo gate
	b.PutCmd("dnf", []string{"--cacheonly", "advisory", "list", "--security", "--quiet"}, out, 0)     // DNF5 path (exit 0 → no DNF4 fallback)
	return b
}

func bundleAPT(out string) *source.Bundle {
	b := source.NewBundle()
	b.PutCmd("apt-get", []string{"--version"}, "apt 2.6.1\n", 0) // detection picks apt (zypper/dnf --version unseeded)
	b.PutCmd("dpkg", []string{"--audit"}, "", 0)                 // aptDBHealth clean
	b.PutFile("/etc/apt/sources.list", []byte("deb http://security.debian.org/debian-security stable-security main\n"))
	b.PutCmd("apt-get", []string{"-s", "upgrade"}, out, 0)
	return b
}

func bundleZypper(out string) *source.Bundle {
	b := source.NewBundle()
	b.PutCmd("zypper", []string{"--version"}, "zypper 1.14.68\n", 0) // detection picks zypper (probed first)
	seedRPMDBHealthy(b)
	b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "list-patches", "--category", "security"}, out, 0)
	b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "repos"}, "1 | update-repo | openSUSE-Update | Yes | refresh\n", 0) // HasSecurityRepo=true
	return b
}

func bundleTDNF(out string) *source.Bundle {
	b := source.NewBundle()
	b.PutCmd("tdnf", []string{"--version"}, "tdnf 3.5.2\n", 0) // detection picks tdnf (zypper/dnf/apt-get --version unseeded)
	seedRPMDBHealthy(b)
	b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0) // tdnfHasEnabledRepo gate
	b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"}, out, 0)
	return b
}

// distro bundles one package manager's rendered output + replay seeds.
type distro struct {
	name   string
	render func([]nonCritClass) string
	bundle func(string) *source.Bundle
}

func crossDistros() []distro {
	return []distro{
		{"dnf", renderDNF4, bundleDNF},
		{"apt", renderAPT, bundleAPT},
		{"zypper", renderZypper, bundleZypper},
		{"tdnf", renderTDNF, bundleTDNF},
	}
}

// driveOne runs the REAL PackagesCollector.Collect over the distro's replay
// bundle, then the REAL ApplyThresholds, and returns the collector result and the
// security-update insights (the scoped fact under test).
func driveOne(tb testing.TB, d distro, classes []nonCritClass) (*models.PackagesInfo, []models.Insight) {
	tb.Helper()
	b := d.bundle(d.render(classes))
	prev := collectors.SetSource(source.NewReplay(b))
	defer collectors.SetSource(prev)

	data, err := collectors.NewPackagesCollector().Collect(context.Background())
	if err != nil {
		tb.Fatalf("%s: Collect returned error: %v", d.name, err)
	}
	info, ok := data.(*models.PackagesInfo)
	if !ok || info == nil {
		tb.Fatalf("%s: Collect returned %T, want *models.PackagesInfo", d.name, data)
	}
	if info.PackageManager != d.name {
		tb.Fatalf("%s: detection selected %q, not %q — seed/detection drift", d.name, info.PackageManager, d.name)
	}
	thresh := DefaultThresholds(platform.EnvBareMetal)
	all := ApplyThresholds([]runner.Result{{Name: "Packages", Data: info}}, thresh, platform.EnvBareMetal, platform.ContainerContext{})
	return info, securityUpdateInsights(all)
}

// securityUpdateInsights scopes the analyzer output to the security-UPDATE
// verdict (the fact under test), excluding DB-health and stale-metadata insights
// (different facts; seeded clean). Every securityUpdateInsight branch
// (heuristics_packages.go:206-246) contains "security update" in its message.
func securityUpdateInsights(ins []models.Insight) []models.Insight {
	var out []models.Insight
	for _, i := range ins {
		if i.Check == "Packages" && strings.Contains(strings.ToLower(i.Message), "security update") {
			out = append(out, i)
		}
	}
	return out
}

// worstClass returns the worst insight level ("CRIT" > "WARN" > "INFO"), or
// "none" for an empty set — the security-update VERDICT CLASS.
func worstClass(ins []models.Insight) string {
	rank := map[string]int{"INFO": 1, "WARN": 2, "CRIT": 3}
	best, name := 0, "none"
	for _, i := range ins {
		if rank[i.Level] > best {
			best, name = rank[i.Level], i.Level
		}
	}
	return name
}

func FuzzPackagesCrossDistroVerdictDifferential(f *testing.F) {
	ds := crossDistros()

	// POSITIVE CONTROL — the plumbing must not be vacuous: a known non-critical
	// mixed set must drive all four collectors to the same non-zero count AND a
	// WARN verdict with exactly one security-update insight each, or every later
	// comparison could pass trivially against four silently-empty parsers.
	ctrl := []nonCritClass{clsImportant, clsModerate, clsLow, clsImportant}
	for _, d := range ds {
		info, sui := driveOne(f, d, ctrl)
		if info.SecurityUpdates != len(ctrl) {
			f.Fatalf("positive control: %s SecurityUpdates=%d, want %d — plumbing is vacuous", d.name, info.SecurityUpdates, len(ctrl))
		}
		if len(sui) != 1 {
			f.Fatalf("positive control: %s produced %d security-update insights, want 1: %+v", d.name, len(sui), sui)
		}
		if worstClass(sui) != "WARN" {
			f.Fatalf("positive control: %s verdict class=%q, want WARN", d.name, worstClass(sui))
		}
	}

	f.Add([]byte{0})             // one important
	f.Add([]byte{1, 2})          // moderate + low
	f.Add([]byte{0, 1, 2, 0, 1}) // mixed non-critical
	f.Add([]byte{})              // empty — all zero, still must agree
	f.Add([]byte{3, 4, 5, 255})  // arbitrary bytes fold into the non-critical classes

	f.Fuzz(func(t *testing.T, raw []byte) {
		classes := classesFromBytes(raw)
		n := len(classes)

		start := time.Now()
		type obs struct {
			sec   int
			class string
			count int
		}
		results := make(map[string]obs, len(ds))
		for _, d := range ds {
			info, sui := driveOne(t, d, classes)
			results[d.name] = obs{sec: info.SecurityUpdates, class: worstClass(sui), count: len(sui)}
		}
		if elapsed, _ := fuzzutil.EffectiveElapsed(start); elapsed > crossDistroVerdictWorkCeiling {
			t.Fatalf("BOUNDED WORK: driving four collectors+analysis took %s (> %s) for %d updates — accumulation/sleep blow-up",
				elapsed, crossDistroVerdictWorkCeiling, n)
		}

		// Per-iteration vacuity guard: dnf must have consumed the whole set, else a
		// mutation that silently dropped every line would make the differential pass
		// trivially (0==0==0==0) while hiding a real miss.
		if results["dnf"].sec != n {
			t.Fatalf("dnf consumed %d of %d logical updates — parse dropped records (classes=%v)", results["dnf"].sec, n, classes)
		}

		// Expected non-vacuous shape for the chosen (non-critical) abstract set.
		wantClass := "none"
		wantCount := 0
		if n > 0 {
			wantClass, wantCount = "WARN", 1
		}

		base := results["dnf"]
		for _, d := range ds {
			r := results[d.name]
			// O1 COUNT: SecurityUpdates agree across all four dialects.
			if r.sec != base.sec {
				t.Fatalf("CROSS-DISTRO SecurityUpdates DIVERGENCE: %s=%d dnf=%d (N=%d, classes=%v)", d.name, r.sec, base.sec, n, classes)
			}
			// O2 VERDICT CLASS: security-update verdict class agrees across all four.
			if r.class != wantClass {
				t.Fatalf("CROSS-DISTRO VERDICT DIVERGENCE: %s class=%q, want %q (all four must agree; N=%d, classes=%v)", d.name, r.class, wantClass, n, classes)
			}
			// O3 INSIGHT COUNT: number of security-update insights agrees across all four.
			if r.count != wantCount {
				t.Fatalf("CROSS-DISTRO INSIGHT-COUNT DIVERGENCE: %s count=%d, want %d (N=%d, classes=%v)", d.name, r.count, wantCount, n, classes)
			}
		}
	})
}
