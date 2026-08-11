package cis

import "github.com/keyorixhq/dashdiag/internal/models"

// Rule is a single CIS/STIG benchmark check.
// StigID maps this check to its DISA STIG equivalent (DISA STIG Ubuntu 20.04 LTS V1R11).
// Empty StigID means the check has no direct STIG equivalent.
type Rule struct {
	ID          string
	StigID      string // DISA STIG ID, e.g. "V-238217" — empty if no STIG mapping
	Framework   string // "CIS", "STIG", or "BOTH"
	Level       int    // 1 = basic, 2 = advanced
	Section     string
	Description string
	// StigDescription overrides Description when running in STIG mode.
	// Empty means use the same Description for both frameworks.
	StigDescription string
	Check           func(sec models.SecurityInfo, ks models.KernelSecurityInfo) models.CISResult
}

// helpers keep Check functions concise
func pass(r Rule) models.CISResult {
	return models.CISResult{ID: r.ID, Framework: r.Framework, Level: r.Level,
		Section: r.Section, Description: r.Description, Status: models.CISPass}
}

func failr(r Rule, finding, fix string) models.CISResult {
	return models.CISResult{ID: r.ID, Framework: r.Framework, Level: r.Level,
		Section: r.Section, Description: r.Description,
		Status: models.CISFail, Finding: finding, Remediation: fix}
}

func skipr(r Rule, reason string) models.CISResult {
	return models.CISResult{ID: r.ID, Framework: r.Framework, Level: r.Level,
		Section: r.Section, Description: r.Description,
		Status: models.CISSkipped, Finding: reason}
}

// unverifiedr is skipr's sibling for the OTHER shape of "skip": the check
// could not be completed (unreadable file, permission denied, unparseable
// output), so the compliance state is genuinely unknown — not confirmed
// absent/not-applicable the way a plain skipr (e.g. "rsync not installed")
// is. Status stays CISSkipped (no wire-format break for existing consumers
// filtering on Status=="SKIP"); Unverified=true is what lets the renderer and
// the NIS2/BSI rollups tell the two apart.
func unverifiedr(r Rule, reason string) models.CISResult {
	return models.CISResult{ID: r.ID, Framework: r.Framework, Level: r.Level,
		Section: r.Section, Description: r.Description,
		Status: models.CISSkipped, Finding: reason, Unverified: true}
}
