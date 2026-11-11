//go:build linux

package collectors

// FuzzSecurityUpdatesCrossDistroDifferential is a CROSS-DISTRO DIFFERENTIAL
// verdict-integrity fuzzer (D1 item 3). The same logical set of pending security
// updates, rendered in three different package-manager dialects, must yield the
// same SecurityUpdates verdict.
//
// It drives the REAL collectors — collectDNF, collectAPT, collectZypper — through
// the `source.NewReplay(bundle)` seam (the exact idiom FuzzCollectDNFVerdict uses),
// so there is NO second implementation of any parser: the oracle is the agreement
// BETWEEN three independent production parsers fed equivalent inputs, not a
// hand-rolled model. A divergence is a real verdict-integrity bug — dashdiag
// reporting a different number of pending security updates on an openSUSE host
// than it would for the identical logical state on a Debian or Fedora host.
//
// The fuzz input is a list of severity classes (one per logical update). Each
// class is rendered into the dialect each collector actually parses:
//
//	class       dnf advisory line (DNF4)        apt `Inst` line                 zypper list-patches row
//	critical    "<ID> Critical/Sec. <pkg>"      pkg in apt criticalPkgs set     "...|security|critical|...|needed|..."
//	important   "<ID> Important/Sec. <pkg>"     pkg NOT in the set              "...|security|important|...|needed|..."
//	other       "<ID> Moderate/Sec. <pkg>"      pkg NOT in the set              "...|security|moderate|...|needed|..."
//
// Oracles (all EQUALITIES that must hold for any correct implementation; no
// "must be healthy", no false-positive direction):
//
//   - O-B1 TOTAL: dnf.SecurityUpdates == apt.SecurityUpdates == zypper.SecurityUpdates == N.
//     This IS "the same SecurityUpdates verdict" the task names.
//   - O-B2 CRITICAL: the Critical sub-count is equal across all three. Sound because
//     the class→dialect mapping drives Critical in each parser's own way (dnf: the
//     "Critical" advisory label, packages_linux.go:387-389; apt: a critical PACKAGE
//     NAME, :547-554; zypper: the "critical" severity column, :774-775), so a
//     critical logical update increments Critical in all three and a non-critical one
//     in none.
//   - O-B3 IMPORTANT (dnf vs zypper only): dnf.Important == zypper.Important. Both
//     derive Important from the advisory's own severity label with identical
//     Moderate-excluded semantics. apt is DELIBERATELY EXCLUDED here: apt has no
//     advisory severity and folds every non-critical security update into Important
//     (no Moderate/Low tier, :546,556) — an EXPECTED DIFFERENCE, not a bug, so
//     asserting apt.Important against the others would be an unsound (false-positive)
//     oracle.
//
// What this oracle does NOT verify (stated per the task's honesty requirement):
//   - apt's Important/Moderate split (expected difference, above).
//   - Behaviour on malformed/partial/hostile tool output — this harness feeds
//     well-formed dialect for each distro; the per-parser replay fuzzers
//     (FuzzCollectDNFReplay/Verdict, FuzzAptAccumulateUpdate*) own that surface.
//   - ESM / Kali-rolling / zypper-lock-retry sub-paths — seeded to no-op so they
//     cannot perturb the three counts under comparison.
//   - CVE severity CORRECTNESS (whether "openssl" truly warrants Critical) — only
//     that the three parsers agree given the same logical input.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// crossDistroWorkCeiling is a loose HANG/blow-up backstop (not a tight perf
// bound): driving the three collectors over ≤256 recorded lines each is
// milliseconds; a returning iteration this slow is a genuine accumulation/sleep
// blow-up, not rig jitter. Loose on purpose so shared-host load never flakes it.
// 30s mirrors cmd/replay_wholebundle_fuzz_test.go's wholeBundleWorkCeiling: loose
// enough that a descheduled worker on a loaded shared host (GOMAXPROCS=2 under
// `nice` alongside other sessions) never flakes, tight enough that a true
// super-linear blow-up over an in-memory bundle is unambiguous.
const crossDistroWorkCeiling = 30 * time.Second

type sevClass uint8

const (
	sevCrit  sevClass = iota // → dnf "Critical", apt critical package, zypper "critical"
	sevImp                   // → dnf "Important", apt non-critical package, zypper "important"
	sevOther                 // → dnf "Moderate",  apt non-critical package, zypper "moderate"
)

// aptCriticalPkg is a package name present in collectAPT's criticalPkgs set
// (packages_linux.go:494-504) so an apt "Inst openssl ..." line classifies
// Critical. aptPlainPkg is deliberately NOT in that set.
const (
	aptCriticalPkg = "openssl"
	aptPlainPkg    = "fuzzplainpkg"
)

// classesFromBytes maps each fuzz byte to one logical update's severity class,
// capping the count so the pipeline stays bounded regardless of input size.
func classesFromBytes(raw []byte) []sevClass {
	const maxUpdates = 256
	if len(raw) > maxUpdates {
		raw = raw[:maxUpdates]
	}
	out := make([]sevClass, 0, len(raw))
	for _, b := range raw {
		out = append(out, sevClass(b%3))
	}
	return out
}

// renderDNF builds `dnf advisory list --security` output (DNF4 tabular form:
// "ADVISORY SEVERITY/Sec. PACKAGE") for the logical set.
func renderDNF(classes []sevClass) string {
	var b strings.Builder
	for i, c := range classes {
		label := "Moderate"
		switch c {
		case sevCrit:
			label = "Critical"
		case sevImp:
			label = "Important"
		}
		fmt.Fprintf(&b, "RHSA-2024:%04d %s/Sec. pkg%d-1.0.x86_64\n", i, label, i)
	}
	return b.String()
}

// renderAPT builds `apt-get -s upgrade` output. Every line is a security line
// (contains "-security"); critical class uses a package in apt's criticalPkgs set.
func renderAPT(classes []sevClass) string {
	var b strings.Builder
	for i, c := range classes {
		pkg := aptPlainPkg
		if c == sevCrit {
			pkg = aptCriticalPkg
		}
		// "Inst <pkg> [old] (new Debian-Security:stable/updates [amd64])"
		fmt.Fprintf(&b, "Inst %s [1.0-%d] (1.1-%d Debian-Security:stable/updates [amd64])\n", pkg, i, i)
	}
	return b.String()
}

// renderZypper builds `zypper list-patches --category security` pipe-table output.
// Columns: Repository | Name | Category | Severity | Interactive | Status | Summary
func renderZypper(classes []sevClass) string {
	var b strings.Builder
	b.WriteString("Repository | Name | Category | Severity | Interactive | Status | Summary\n")
	b.WriteString("-----------+------+----------+----------+-------------+--------+--------\n")
	for i, c := range classes {
		sev := "moderate"
		switch c {
		case sevCrit:
			sev = "critical"
		case sevImp:
			sev = "important"
		}
		fmt.Fprintf(&b, "update-repo | patch-%d | security | %s | --- | needed | fix-%d\n", i, sev, i)
	}
	return b.String()
}

// countExpected returns (total, criticals, importants) for the logical set —
// used only for the positive-control and vacuity guards, never as the primary
// oracle (the primary oracle is parser-vs-parser agreement).
func countExpected(classes []sevClass) (total, crit, imp int) {
	total = len(classes)
	for _, c := range classes {
		switch c {
		case sevCrit:
			crit++
		case sevImp:
			imp++
		}
	}
	return
}

// drive runs one collector under a replay bundle built by seedFn and returns its info.
func driveCollector(tb testing.TB, seedFn func(*source.Bundle), run func(context.Context) (*models.PackagesInfo, error), what string) *models.PackagesInfo {
	tb.Helper()
	b := source.NewBundle()
	seedFn(b)
	prev := SetSource(source.NewReplay(b))
	defer SetSource(prev)
	info, err := run(context.Background())
	if err != nil {
		tb.Fatalf("%s returned error on recorded exit-0 output: %v", what, err)
	}
	if info == nil {
		tb.Fatalf("%s returned nil info with nil error", what)
	}
	return info
}

func seedDNF(dnfOut string) func(*source.Bundle) {
	return func(b *source.Bundle) {
		// Gate: at least one enabled repo so collectDNF reaches the parse loop.
		b.PutCmd("dnf", []string{dnfCacheOnly, "repolist", "--enabled", pkgFlagQ}, "baseos\nappstream\n", 0)
		// DNF5 advisory query (tried first); exit 0 so the DNF4 fallback is not taken.
		b.PutCmd("dnf", []string{dnfCacheOnly, "advisory", "list", flagSecurity, flagQuiet}, dnfOut, 0)
	}
}

func seedAPT(aptOut string) func(*source.Bundle) {
	return func(b *source.Bundle) {
		// aptHasSecurityRepo reads /etc/apt/sources.list — seed a security repo line.
		b.PutFile("/etc/apt/sources.list", []byte("deb http://security.debian.org/debian-security stable-security main\n"))
		// isKali reads /etc/os-release — leave unseeded (readFile errors → not Kali).
		b.PutCmd(pkgCmdAptGet, []string{"-s", "upgrade"}, aptOut, 0)
		// checkESMUpdates runs `pro security-status --format json` — left unseeded → skipped.
	}
}

func seedZypper(zypperOut string) func(*source.Bundle) {
	return func(b *source.Bundle) {
		// Main query (runCmdCombined — stdout is enough since exit 0).
		b.PutCmd("zypper", []string{pkgNonInteractive, pkgFlagNoColor, "list-patches", "--category", pkgSevSecurity}, zypperOut, 0)
		// zypperHasSecurityRepo: `zypper repos` with an "update" keyword → HasSecurityRepo=true
		// (affects Status only, not the counts under test, but keeps the result clean).
		b.PutCmd("zypper", []string{pkgNonInteractive, pkgFlagNoColor, "repos"}, "1 | update-repo | openSUSE-Update | Yes | refresh\n", 0)
		// checkSUSEMigrationRisks runs extra commands — left unseeded → empty, no count effect.
	}
}

func FuzzSecurityUpdatesCrossDistroDifferential(f *testing.F) {
	// POSITIVE CONTROL — the plumbing must not be vacuous: a known mixed set must
	// drive all three collectors to the same non-zero total, or every later
	// comparison could pass trivially against three silently-empty parsers.
	ctrl := []sevClass{sevCrit, sevImp, sevOther, sevImp, sevCrit}
	wantTotal, wantCrit, wantImp := countExpected(ctrl)
	dnfC := driveCollector(f, seedDNF(renderDNF(ctrl)), collectDNF, "collectDNF(ctrl)")
	aptC := driveCollector(f, seedAPT(renderAPT(ctrl)), collectAPT, "collectAPT(ctrl)")
	zypC := driveCollector(f, seedZypper(renderZypper(ctrl)), collectZypper, "collectZypper(ctrl)")
	for _, got := range []struct {
		name string
		info *models.PackagesInfo
	}{{"dnf", dnfC}, {"apt", aptC}, {"zypper", zypC}} {
		if got.info.SecurityUpdates != wantTotal {
			f.Fatalf("positive control: %s SecurityUpdates=%d, want %d — plumbing is vacuous", got.name, got.info.SecurityUpdates, wantTotal)
		}
	}
	if dnfC.CriticalUpdates != wantCrit || zypC.CriticalUpdates != wantCrit || aptC.CriticalUpdates != wantCrit {
		f.Fatalf("positive control: Critical counts dnf=%d apt=%d zyp=%d, want %d", dnfC.CriticalUpdates, aptC.CriticalUpdates, zypC.CriticalUpdates, wantCrit)
	}
	if dnfC.ImportantUpdates != wantImp || zypC.ImportantUpdates != wantImp {
		f.Fatalf("positive control: Important counts dnf=%d zyp=%d, want %d", dnfC.ImportantUpdates, zypC.ImportantUpdates, wantImp)
	}

	f.Add([]byte{0})             // one critical
	f.Add([]byte{1, 2})          // important + other
	f.Add([]byte{0, 1, 2, 0, 1}) // mixed
	f.Add([]byte{})              // empty — all zero, still must agree
	f.Add([]byte{3, 4, 5, 255})  // arbitrary bytes fold into the 3 classes

	f.Fuzz(func(t *testing.T, raw []byte) {
		classes := classesFromBytes(raw)
		total, crit, imp := countExpected(classes)

		start := time.Now()
		dnf := driveCollector(t, seedDNF(renderDNF(classes)), collectDNF, "collectDNF")
		apt := driveCollector(t, seedAPT(renderAPT(classes)), collectAPT, "collectAPT")
		zyp := driveCollector(t, seedZypper(renderZypper(classes)), collectZypper, "collectZypper")
		if elapsed := time.Since(start); elapsed > crossDistroWorkCeiling {
			t.Fatalf("BOUNDED WORK: driving the three collectors took %s (> %s) for %d logical updates — accumulation/sleep blow-up",
				elapsed, crossDistroWorkCeiling, len(classes))
		}

		// Per-iteration vacuity guard: each parser must have actually consumed the
		// logical set (else a mutation that silently dropped every line would make
		// the differential pass trivially at 0==0==0 while hiding a real miss).
		if dnf.SecurityUpdates != total {
			t.Fatalf("dnf consumed %d of %d logical updates — parse dropped records (input classes=%v)", dnf.SecurityUpdates, total, classes)
		}

		// O-B1 TOTAL agreement across all three dialects.
		if !(dnf.SecurityUpdates == apt.SecurityUpdates && apt.SecurityUpdates == zyp.SecurityUpdates) {
			t.Fatalf("CROSS-DISTRO SecurityUpdates DIVERGENCE: dnf=%d apt=%d zypper=%d (logical N=%d, classes=%v)",
				dnf.SecurityUpdates, apt.SecurityUpdates, zyp.SecurityUpdates, total, classes)
		}

		// O-B2 CRITICAL agreement across all three.
		if !(dnf.CriticalUpdates == apt.CriticalUpdates && apt.CriticalUpdates == zyp.CriticalUpdates && dnf.CriticalUpdates == crit) {
			t.Fatalf("CROSS-DISTRO Critical DIVERGENCE: dnf=%d apt=%d zypper=%d (want %d, classes=%v)",
				dnf.CriticalUpdates, apt.CriticalUpdates, zyp.CriticalUpdates, crit, classes)
		}

		// O-B3 IMPORTANT agreement dnf vs zypper (apt excluded by design, F5).
		if !(dnf.ImportantUpdates == zyp.ImportantUpdates && dnf.ImportantUpdates == imp) {
			t.Fatalf("dnf/zypper Important DIVERGENCE: dnf=%d zypper=%d (want %d, classes=%v)",
				dnf.ImportantUpdates, zyp.ImportantUpdates, imp, classes)
		}
	})
}
