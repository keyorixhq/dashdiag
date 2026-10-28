package models

// Coverage says, for one check of a run, whether dsd actually looked. It is the
// answer to "did this pass, or did it not get checked?" that status alone cannot
// give: a check that needs root and ran as nobody, a collector that timed out
// and a host without a GPU must not all read like "looked, fine".
//
// The derivation lives in ONE place, render.Coverage (next to render.Verdict);
// nothing else computes it. The vocabulary is additive to the output contract
// (COMPATIBILITY.md): it never changes the meaning of status or the verdict.
const (
	// CoverageChecked: the check ran and produced a result. A check that ran
	// but could not read part of what it checks is still checked and lists the
	// part in NotCheckedSubchecks.
	CoverageChecked = "checked"
	// CoverageNotChecked: dsd did not look (the collector errored, timed out, or
	// the thing it checks could not be read at all). The verdict floors on it
	// unless the reason is needs_root (see render.Verdict).
	CoverageNotChecked = "not_checked"
	// CoverageNotApplicable: there is nothing to check on this host (no GPU, no
	// Docker, not a cloud VM, a collector that does not exist on this platform).
	// Never raises the verdict.
	CoverageNotApplicable = "not_applicable"
)

// Coverage reasons (CheckCoverage.Reason, the machine-friendly
// "coverage_reason"). The list is closed per release: adding one is additive,
// renaming or removing one is breaking. CoverageReasons is the guard's copy.
const (
	// not_checked reasons
	ReasonNeedsRoot      = "needs_root"      // a root-only read on a non-root run: re-run with sudo
	ReasonTimeout        = "timeout"         // the collector did not finish in time
	ReasonUnreadable     = "unreadable"      // the collector failed on a permission error
	ReasonCollectorError = "collector_error" // the collector returned an error or panicked
	ReasonUnverified     = "unverified"      // ran, but could not determine what it checks (not root-only)
	// not_applicable reasons
	ReasonNotPresent           = "not_present"            // the host has nothing of this kind (no GPU, no Docker, ...)
	ReasonNotSupportedPlatform = "not_supported_platform" // the collector does not exist on this platform
)

// CoverageReasons is every reason value, for documentation and the guard.
var CoverageReasons = []string{
	ReasonNeedsRoot, ReasonTimeout, ReasonUnreadable, ReasonCollectorError, ReasonUnverified,
	ReasonNotPresent, ReasonNotSupportedPlatform,
}

// SubCheck is one part of a check that was not looked at.
type SubCheck struct {
	Check   string `json:"check" yaml:"check"`
	Reason  string `json:"reason" yaml:"reason"`
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}

// CheckCoverage is the coverage of one collector result.
type CheckCoverage struct {
	Name     string `json:"name" yaml:"name"`
	Coverage string `json:"coverage" yaml:"coverage"`
	Reason   string `json:"coverage_reason,omitempty" yaml:"coverage_reason,omitempty"`
	// NotCheckedSubchecks lists the parts that were not looked at: on a "checked"
	// check, the part it could not read; on a "not_checked" check that is
	// absent-but-unverified, the findings that say why. Empty when the whole
	// check simply errored (the reason says it).
	NotCheckedSubchecks []SubCheck `json:"not_checked_subchecks,omitempty" yaml:"not_checked_subchecks,omitempty"`
}

// CoverageSummary is the coverage of a whole run.
type CoverageSummary struct {
	// Checked counts checks that ran (including partially checked ones).
	Checked int `json:"checked"`
	// NotChecked counts things that were not looked at: whole checks that did
	// not run plus the sub-checks of partially checked ones, one per distinct
	// check name. It equals Verdict.NotRun + Verdict.Skipped for a run whose
	// insights came from analysis.ApplyThresholds.
	NotChecked    int `json:"not_checked"`
	NotApplicable int `json:"not_applicable"`
	// Partial is how many of the Checked ran only partly.
	Partial int `json:"partial,omitempty"`
	// Reasons counts the NotChecked items by reason.
	Reasons map[string]int `json:"not_checked_reasons,omitempty"`
	// Checks is every collector result, including the not-applicable ones that
	// checks[] omits. Sorted by name.
	Checks []CheckCoverage `json:"checks,omitempty"`
}
