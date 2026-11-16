//go:build unix

package cis

// XD1 Target B — CIS compliance verdict must be CROSS-DISTRO STABLE.
//
// cis.Evaluate(sec, ks, level, stig, pkgMgr) takes a package-manager string so
// it can tailor *remediation commands* to the host's distro family (apt vs dnf
// vs zypper vs pacman — see remediation.go/adaptRemediation). The security
// VERDICT, however, must depend only on the measured state (sec, ks, level,
// stig): the same logical system state expressed on Debian, RHEL, SUSE, Arch or
// Alpine must yield the identical per-rule Status. A PASS on one distro and a
// FAIL on another for the same state would be a cross-distro verdict
// disagreement — exactly the class XD1 is asked to rule out.
//
// This is the in-repo analogue of the capture-replay cross-distro differential:
// rather than two distro captures of one logical state (the external captures
// directory is outside this session's sandbox), it varies the distro axis
// directly at the verdict seam and requires agreement.
//
// Oracle (per fuzzed (sec, ks, level, stig), comparing every pkgMgr against a
// reference pkgMgr):
//   O-1  SAME SHAPE: identical rule count and, position-for-position, identical
//        ID / Status / Finding / Section / Level / Description.
//   O-2  REMEDIATION DIFFERENCE IS DOCUMENTED: a Remediation string may differ
//        across pkgMgr ONLY when the rule FAILed AND its ID is in the known
//        adaptable set (adaptRemediation's switch). Any other Remediation
//        divergence is a pkgMgr leak into a verdict-adjacent field.
//   O-3  VALID VERDICT: every Status is one of the five CISStatus values and the
//        report counters sum to len(Results) — no empty/undefined verdict.
//   O-4  BOUNDED: Evaluate stays within the resource allocation/time budget for
//        every fuzzed input, including adversarially large account/sudo slices.
//
// Discovery expectation is stated honestly in the XD1 report: Status is
// pkgMgr-invariant by construction today (only adaptRemediation consumes
// pkgMgr, and only on FAIL.Remediation), so O-1/O-2 are primarily a standing
// REGRESSION guard against a future change wiring pkgMgr into a verdict; O-3/O-4
// are the active-discovery oracles (undefined verdict / allocation blow-up on a
// hostile SecurityInfo).
//
// Resource meters enabled: TotalAlloc + wall time. Not metered: filesystem
// (Evaluate reads host /etc,/proc paths read-only and identically across the
// pkgMgr axis, so a fingerprint would add nothing the read-only RO1/DL1 targets
// don't already cover) and goroutines (Evaluate spawns none).

import (
	"fmt"
	"sync"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// xd1PkgMgrs spans the distro families dsd supports: apt (Debian/Ubuntu/SteamOS),
// dnf+yum+tdnf (RHEL/Fedora/Photon), zypper (SUSE), pacman (Arch), apk (Alpine),
// and "" (unknown). The verdict must be identical across all of them.
var xd1PkgMgrs = []string{"apt", "dnf", "yum", "tdnf", "zypper", "pacman", "apk", ""}

// xd1AdaptableCISIDs is the exact set of CIS rule IDs adaptRemediation rewrites
// by pkgMgr (kept in sync with remediation.go's switch).
var xd1AdaptableCISIDs = map[string]bool{
	"1.3.1": true, "2.1.1": true, "3.3.1": true, "3.5.1": true, "3.5.1.1": true,
	"3.5.1.2": true, "4.1.1": true, "4.1.2": true, "5.3.1": true, "4.2.1": true, "1.6.1": true,
}

// adaptableFinalIDs returns the set of FINAL report IDs that may legitimately
// carry a pkgMgr-dependent Remediation. adaptRemediation matches on the CIS rule
// ID, but in STIG mode Evaluate then relabels the result to the rule's StigID
// (e.g. 4.1.2 → V-238361), so the final ID can be either. Computed lazily (not a
// package-var initializer) because CISRules is populated in rules.go's init(),
// which runs after var initializers — the harness must track the ID swap, not
// weaken the oracle.
var (
	xd1AdaptableOnce  sync.Once
	xd1AdaptableFinal map[string]bool
)

func adaptableFinalIDs() map[string]bool {
	xd1AdaptableOnce.Do(func() {
		m := map[string]bool{}
		for id := range xd1AdaptableCISIDs {
			m[id] = true
		}
		for _, r := range CISRules {
			if xd1AdaptableCISIDs[r.ID] && r.StigID != "" {
				m[r.StigID] = true
			}
		}
		xd1AdaptableFinal = m
	})
	return xd1AdaptableFinal
}

func xd1ValidStatus(s models.CISStatus) bool {
	switch s {
	case models.CISPass, models.CISFail, models.CISManual, models.CISNotApplicable, models.CISSkipped:
		return true
	}
	return false
}

// crossDistroViolations compares reference report ref against other and returns
// any verdict-stability breaches.
func crossDistroViolations(refMgr, otherMgr string, ref, other models.CISReport) []string {
	var v []string
	if len(ref.Results) != len(other.Results) {
		return []string{fmt.Sprintf("rule count differs: %s=%d vs %s=%d",
			refMgr, len(ref.Results), otherMgr, len(other.Results))}
	}
	for i := range ref.Results {
		a, b := ref.Results[i], other.Results[i]
		if a.ID != b.ID || a.Status != b.Status || a.Finding != b.Finding ||
			a.Section != b.Section || a.Level != b.Level || a.Description != b.Description {
			v = append(v, fmt.Sprintf("rule %s: verdict differs between %s and %s (status %s/%s, finding %q/%q)",
				a.ID, refMgr, otherMgr, a.Status, b.Status, a.Finding, b.Finding))
			continue
		}
		if a.Remediation != b.Remediation {
			if a.Status != models.CISFail || !adaptableFinalIDs()[a.ID] {
				v = append(v, fmt.Sprintf("rule %s: Remediation differs across pkgMgr (%s vs %s) but rule is not an adaptable FAIL (status=%s)",
					a.ID, refMgr, otherMgr, a.Status))
			}
		}
	}
	return v
}

// strs builds a deterministic slice of n synthetic account/entry names.
func strs(prefix string, n int) []string {
	if n <= 0 {
		return nil
	}
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return out
}

func xd1Evaluate(sec models.SecurityInfo, ks models.KernelSecurityInfo, level int, stig bool, mgr string) models.CISReport {
	return Evaluate(sec, ks, level, stig, mgr)
}

func validateReport(rep models.CISReport) string {
	for _, r := range rep.Results {
		if !xd1ValidStatus(r.Status) {
			return fmt.Sprintf("rule %s has invalid status %q", r.ID, r.Status)
		}
	}
	if rep.Pass+rep.Fail+rep.Manual+rep.NA+rep.Skipped != len(rep.Results) {
		return fmt.Sprintf("counters (%d+%d+%d+%d+%d) != results %d",
			rep.Pass, rep.Fail, rep.Manual, rep.NA, rep.Skipped, len(rep.Results))
	}
	if rep.Unverified > rep.Skipped {
		return fmt.Sprintf("Unverified %d > Skipped %d", rep.Unverified, rep.Skipped)
	}
	return ""
}

func FuzzCISEvaluateCrossDistroVerdictStable(f *testing.F) {
	f.Add(uint8(1), false, -1, uint8(0), uint8(0), uint8(0), false, false, false, false, "")
	f.Add(uint8(2), true, 5, uint8(3), uint8(1), uint8(2), true, true, true, true, "sshd -T")
	f.Add(uint8(2), false, 0, uint8(0), uint8(0), uint8(0), false, true, false, false, "file")
	f.Add(uint8(1), false, 10, uint8(255), uint8(0), uint8(0), false, false, false, false, "")

	f.Fuzz(func(t *testing.T,
		levelByte uint8, stig bool, auditRules int,
		nNopasswd, nUID0, nEmpty uint8,
		shadowUnreadable, sudoersUnreadable, sshConfigUnreadable, auditUnreadable bool,
		sshSource string,
	) {
		level := int(levelByte%2) + 1 // 1 or 2
		sec := models.SecurityInfo{
			AuditRules:            auditRules,
			SudoNopasswd:          strs("np", int(nNopasswd)),
			UID0Users:             strs("u", int(nUID0)),
			EmptyPasswordAccounts: strs("e", int(nEmpty)),
			ShadowUnreadable:      shadowUnreadable,
			SudoersUnreadable:     sudoersUnreadable,
			SSHConfigUnreadable:   sshConfigUnreadable,
			AuditRulesUnreadable:  auditUnreadable,
			SSHAuditSource:        sshSource,
		}
		ks := models.KernelSecurityInfo{}

		inputLen := int(nNopasswd) + int(nUID0) + int(nEmpty) + len(sshSource) + 16

		var reports []models.CISReport
		resource.Check(t, inputLen, 4096, func() {
			reports = make([]models.CISReport, len(xd1PkgMgrs))
			for i, mgr := range xd1PkgMgrs {
				reports[i] = xd1Evaluate(sec, ks, level, stig, mgr)
			}
		})

		ref := reports[0]
		if msg := validateReport(ref); msg != "" {
			t.Fatalf("invalid verdict (pkgMgr=%q): %s", xd1PkgMgrs[0], msg)
		}
		for i := 1; i < len(reports); i++ {
			if msg := validateReport(reports[i]); msg != "" {
				t.Fatalf("invalid verdict (pkgMgr=%q): %s", xd1PkgMgrs[i], msg)
			}
			if viol := crossDistroViolations(xd1PkgMgrs[0], xd1PkgMgrs[i], ref, reports[i]); len(viol) > 0 {
				t.Fatalf("cross-distro verdict disagreement:\n  %s", viol[0])
			}
		}
	})
}

// TestXD1CrossDistroSeeds runs the differential on every `go test ./internal/cis`
// (no -fuzz), so the oracle is always watched.
func TestXD1CrossDistroSeeds(t *testing.T) {
	secs := []models.SecurityInfo{
		{},
		{ShadowUnreadable: true, SudoersUnreadable: true, SSHConfigUnreadable: true, AuditRulesUnreadable: true},
		{SudoNopasswd: []string{"deploy"}, UID0Users: []string{"backup"}, AuditRules: 0},
		{SSHAuditSource: "sshd -T", AuditRules: 42},
	}
	for _, level := range []int{1, 2} {
		for _, stig := range []bool{false, true} {
			for _, sec := range secs {
				ref := Evaluate(sec, models.KernelSecurityInfo{}, level, stig, xd1PkgMgrs[0])
				if msg := validateReport(ref); msg != "" {
					t.Fatalf("invalid ref verdict: %s", msg)
				}
				for i := 1; i < len(xd1PkgMgrs); i++ {
					other := Evaluate(sec, models.KernelSecurityInfo{}, level, stig, xd1PkgMgrs[i])
					if viol := crossDistroViolations(xd1PkgMgrs[0], xd1PkgMgrs[i], ref, other); len(viol) > 0 {
						t.Errorf("level=%d stig=%v: %s", level, stig, viol[0])
					}
				}
			}
		}
	}
}

// TestXD1CrossDistroRedGreen watches the cross-distro oracle fire: a synthetic
// report whose Status flips across pkgMgr must be flagged, and an identical pair
// must pass.
func TestXD1CrossDistroRedGreen(t *testing.T) {
	base := models.CISReport{Results: []models.CISResult{
		{ID: "9.9.9", Status: models.CISPass, Section: "x", Level: 1, Description: "d"},
	}}
	// GREEN: identical report → no violation.
	if v := crossDistroViolations("apt", "dnf", base, base); len(v) > 0 {
		t.Errorf("GREEN: identical reports flagged: %s", v[0])
	}
	// RED: same rule, Status flipped PASS→FAIL across pkgMgr → must be flagged.
	flipped := models.CISReport{Results: []models.CISResult{
		{ID: "9.9.9", Status: models.CISFail, Section: "x", Level: 1, Description: "d"},
	}}
	if v := crossDistroViolations("apt", "dnf", base, flipped); len(v) == 0 {
		t.Error("RED: oracle failed to flag a Status that flips across pkgMgr")
	}
	// RED: Remediation differs on a non-adaptable PASS rule → must be flagged.
	remDiff := models.CISReport{Results: []models.CISResult{
		{ID: "9.9.9", Status: models.CISPass, Section: "x", Level: 1, Description: "d", Remediation: "pacman -S x"},
	}}
	if v := crossDistroViolations("apt", "dnf", base, remDiff); len(v) == 0 {
		t.Error("RED: oracle failed to flag a pkgMgr-dependent Remediation on a non-adaptable rule")
	}
}
