package cis

import "github.com/keyorixhq/dashdiag/internal/models"

// Rule is a single CIS/STIG benchmark check.
type Rule struct {
	ID          string
	Framework   string // "CIS" or "STIG"
	Level       int    // 1 = basic, 2 = advanced
	Section     string
	Description string
	Check       func(sec models.SecurityInfo, ks models.KernelSecurityInfo) models.CISResult
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
