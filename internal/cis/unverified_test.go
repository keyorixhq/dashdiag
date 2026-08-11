package cis

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestEvaluateUnverifiedSignals guards the false-clean fix for rules that read
// a single SecurityInfo "could not read this file" bool directly: they must
// report Skipped AND Unverified, never a silent NA/Skip that collapses into
// the same bucket as a genuinely-not-applicable rule.
func TestEvaluateUnverifiedSignals(t *testing.T) {
	t.Parallel()
	ks := models.KernelSecurityInfo{}
	find := func(rep models.CISReport, id string) (models.CISResult, bool) {
		for _, r := range rep.Results {
			if r.ID == id {
				return r, true
			}
		}
		return models.CISResult{}, false
	}

	cases := []struct {
		name string
		sec  models.SecurityInfo
		id   string
	}{
		{"shadow unreadable", models.SecurityInfo{ShadowUnreadable: true}, "5.4.2"},
		{"sudoers unreadable", models.SecurityInfo{SudoersUnreadable: true}, "5.3.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rep := Evaluate(tc.sec, ks, 1, false, "apt")
			r, ok := find(rep, tc.id)
			if !ok {
				t.Fatalf("%s not found in report", tc.id)
			}
			if r.Status != models.CISSkipped {
				t.Errorf("%s: status=%v, want Skipped", tc.id, r.Status)
			}
			if !r.Unverified {
				t.Errorf("%s: Unverified=false, want true — must not read as a confirmed-absent skip", tc.id)
			}
			if r.Finding == "" {
				t.Errorf("%s: Finding is empty — renderer has nothing to show for why this is unverified", tc.id)
			}
		})
	}
}

// TestCheckAuditRuleUnverifiedVsSkip guards checkAuditRule's disambiguation
// directly: zero readable audit rule lines must report Unverified when
// auditctl -l was refused (root-only), and a genuine confirmed-absent Skip
// (not Unverified) when it wasn't — the only signal telling those two states
// apart is the auditRulesInaccessible bool, since the file read outcome is
// identical (empty) in both.
//
// Mutates the package-level auditRulesFilePath/auditRulesDPath vars to point
// at a guaranteed-empty temp dir, so no t.Parallel() here — see
// internal/collectors/parallel_mutation_governance_test.go, which fails the
// build if this test (or any ancestor/descendant) both mutates a package var
// and calls t.Parallel() anywhere in the same tree.
func TestCheckAuditRuleUnverifiedVsSkip(t *testing.T) {
	dir := t.TempDir()
	origFile, origDPath := auditRulesFilePath, auditRulesDPath
	auditRulesFilePath = filepath.Join(dir, "audit.rules")   // does not exist
	auditRulesDPath = filepath.Join(dir, "rules.d.notexist") // does not exist
	defer func() { auditRulesFilePath, auditRulesDPath = origFile, origDPath }()

	r := ruleByID("4.1.3")

	unverified := checkAuditRule(r, true, []string{"-w /etc/passwd"}, "fix")
	if unverified.Status != models.CISSkipped || !unverified.Unverified {
		t.Errorf("auditRulesInaccessible=true: status=%v unverified=%v, want Skipped+Unverified",
			unverified.Status, unverified.Unverified)
	}

	genuineSkip := checkAuditRule(r, false, []string{"-w /etc/passwd"}, "fix")
	if genuineSkip.Status != models.CISSkipped || genuineSkip.Unverified {
		t.Errorf("auditRulesInaccessible=false: status=%v unverified=%v, want Skipped, NOT Unverified",
			genuineSkip.Status, genuineSkip.Unverified)
	}
}

// TestEvaluateAuditAmbiguousSiblings guards the Evaluate()-level override: all
// 6 rule IDs in auditVerdictAmbiguousRuleIDs (4.1.1's detail-siblings +
// 4.1.2), not just 4.1.1 itself, must flip to Unverified when
// sec.AuditRulesUnreadable is set — this is what makes the override apply
// uniformly instead of only to the one rule it was first noticed on.
func TestEvaluateAuditAmbiguousSiblings(t *testing.T) {
	t.Parallel()
	ks := models.KernelSecurityInfo{}
	sec := models.SecurityInfo{AuditRulesUnreadable: true}
	rep := Evaluate(sec, ks, 2, false, "apt") // 4.1.1.x detail rules are Level 2

	find := func(id string) (models.CISResult, bool) {
		for _, r := range rep.Results {
			if r.ID == id {
				return r, true
			}
		}
		return models.CISResult{}, false
	}

	for id := range auditVerdictAmbiguousRuleIDs {
		r, ok := find(id)
		if !ok {
			t.Errorf("%s not found in report (level 1 rule missing?)", id)
			continue
		}
		if r.Status != models.CISSkipped || !r.Unverified {
			t.Errorf("%s with AuditRulesUnreadable: status=%v unverified=%v, want Skipped+Unverified",
				id, r.Status, r.Unverified)
		}
	}
}

// TestEvaluateReportUnverifiedTally guards that report.Unverified is a strict
// count of report-wide results with Unverified==true, not just a copy of
// report.Skipped — the two must diverge whenever any skip is genuinely not
// applicable (auditd truly absent, no MTA installed, etc.) rather than
// unreadable.
func TestEvaluateReportUnverifiedTally(t *testing.T) {
	t.Parallel()
	ks := models.KernelSecurityInfo{}

	// All-verified security posture: nothing should be marked Unverified even
	// though some rules will still legitimately Skip (features genuinely absent).
	verified := models.SecurityInfo{SSHAuditSource: "sshd -T"}
	repVerified := Evaluate(verified, ks, 1, false, "apt")
	wantVerified := 0
	for _, r := range repVerified.Results {
		if r.Unverified {
			wantVerified++
		}
	}
	if repVerified.Unverified != wantVerified {
		t.Errorf("report.Unverified=%d, want %d (recount of Unverified==true results)", repVerified.Unverified, wantVerified)
	}
	if repVerified.Unverified >= repVerified.Skipped && repVerified.Skipped > 0 {
		// Not a hard invariant in general, but with a fully-verified SecurityInfo
		// there is at least one genuinely-not-applicable skip in the rule set
		// (e.g. no MTA/no telnet-server installed), so Unverified must be a
		// strict subset here, not equal to Skipped.
		t.Errorf("with a fully verified SecurityInfo, report.Unverified (%d) should be < report.Skipped (%d), "+
			"not equal — otherwise every skip is being misclassified as unverified",
			repVerified.Unverified, repVerified.Skipped)
	}

	// Unreadable-everything posture: shadow/sudoers/ssh/audit all unreadable.
	unreadable := models.SecurityInfo{
		ShadowUnreadable:     true,
		SudoersUnreadable:    true,
		SSHConfigUnreadable:  true,
		AuditRulesUnreadable: true,
	}
	repUnreadable := Evaluate(unreadable, ks, 1, false, "apt")
	wantUnreadable := 0
	for _, r := range repUnreadable.Results {
		if r.Unverified {
			wantUnreadable++
		}
	}
	if repUnreadable.Unverified != wantUnreadable {
		t.Errorf("report.Unverified=%d, want %d (recount of Unverified==true results)", repUnreadable.Unverified, wantUnreadable)
	}
	if repUnreadable.Unverified == 0 {
		t.Error("with shadow/sudoers/ssh/audit all unreadable, report.Unverified must be > 0")
	}
}

// TestGroupByNIS2Unverified guards the NIS2 rollup: an article with at least
// one Pass and at least one Unverified sibling must report "UNVERIFIED", not
// "PASS" — a plain PASS there would be a false-clean compliance verdict, since
// it would certify coverage the scan never actually confirmed.
func TestGroupByNIS2Unverified(t *testing.T) {
	t.Parallel()
	results := []models.CISResult{
		{ID: "5.1.1", Status: models.CISPass, NIS2Refs: []string{nis2ArticleI}},
		{ID: "5.1.2", Status: models.CISSkipped, Unverified: true, NIS2Refs: []string{nis2ArticleI}},
	}
	groups := GroupByNIS2(results)
	var article NIS2ArticleGroup
	found := false
	for _, g := range groups {
		if g.Article.ID == nis2ArticleI {
			article, found = g, true
			break
		}
	}
	if !found {
		t.Fatal("Art.21(2)(i) group not found")
	}
	if article.Status != "UNVERIFIED" {
		t.Errorf("Status=%q, want UNVERIFIED (Pass>0 with an Unverified sibling)", article.Status)
	}
	if article.Unverified != 1 {
		t.Errorf("Unverified=%d, want 1", article.Unverified)
	}

	// Contrast: same shape but the skip is a GENUINE not-applicable (Unverified
	// stays false) — the group must read as a plain PASS, not UNVERIFIED.
	genuineSkip := []models.CISResult{
		{ID: "5.1.1", Status: models.CISPass, NIS2Refs: []string{nis2ArticleI}},
		{ID: "5.1.2", Status: models.CISSkipped, NIS2Refs: []string{nis2ArticleI}},
	}
	for _, g := range GroupByNIS2(genuineSkip) {
		if g.Article.ID == nis2ArticleI && g.Status != "PASS" {
			t.Errorf("Status=%q, want PASS when the sibling skip is genuinely not applicable", g.Status)
		}
	}
}

// TestGroupByBSIUnverified mirrors TestGroupByNIS2Unverified for the BSI
// rollup — same false-clean risk, same fix, different grouping key.
func TestGroupByBSIUnverified(t *testing.T) {
	t.Parallel()
	results := []models.CISResult{
		{ID: "5.4.2", Status: models.CISPass, BSIRefs: []string{bsiSys11A2}},
		{ID: "5.4.3", Status: models.CISSkipped, Unverified: true, BSIRefs: []string{bsiSys11A2}},
	}
	groups := GroupByBSI(results)
	var req BSIReqGroup
	found := false
	for _, g := range groups {
		if g.Req.ID == bsiSys11A2 {
			req, found = g, true
			break
		}
	}
	if !found {
		t.Fatal("SYS.1.1.A2 group not found")
	}
	if req.Status != "UNVERIFIED" {
		t.Errorf("Status=%q, want UNVERIFIED (Pass>0 with an Unverified sibling)", req.Status)
	}
	if req.Unverified != 1 {
		t.Errorf("Unverified=%d, want 1", req.Unverified)
	}

	genuineSkip := []models.CISResult{
		{ID: "5.4.2", Status: models.CISPass, BSIRefs: []string{bsiSys11A2}},
		{ID: "5.4.3", Status: models.CISSkipped, BSIRefs: []string{bsiSys11A2}},
	}
	for _, g := range GroupByBSI(genuineSkip) {
		if g.Req.ID == bsiSys11A2 && g.Status != "PASS" {
			t.Errorf("Status=%q, want PASS when the sibling skip is genuinely not applicable", g.Status)
		}
	}
}
