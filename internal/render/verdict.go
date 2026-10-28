package render

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/store"
)

// This file is the ONE place an overall verdict is derived and the one place
// the all-clear wording ("System healthy", "All checks passed", "HEALTHY", ...)
// lives. DEFECT-CLASSES.md C1: a run whose checks could not run must never
// read as healthy. The C1 fix once reached the exit code, the JSON verdict and
// Nagios only, while the terminal banner, both reports, the history entry and
// the story each re-derived "healthy" from CRIT/WARN counts. Every output now
// asks Verdict; TestGuardB_NoSecondVerdictDerivation fails if one derives its
// own, and TestGuardA_* feeds every output a run that must not read healthy.

// VerdictInfo is the overall verdict of one run.
type VerdictInfo struct {
	// Level is "OK", "WARN" or "CRIT" — the closed vocabulary of the JSON
	// schema, the history store and the exit-code contract.
	Level string

	Crit, Warn, Info int

	// Unverified counts insights flagged Unverified: the check ran but could
	// not determine the thing it checks (permission denied, unreadable file).
	Unverified int
	// Errored counts collectors that failed outright (Result.Err != nil).
	Errored int
	// NotRun is the number of distinct checks that could not run: the union of
	// errored collectors and unverified insights. It is what the user is told.
	// Checks that only a root run can read (NeedsRoot) are not in it: they are
	// counted in Skipped.
	NotRun int
	// NeedsRoot counts the Unverified insights that could only be read as root
	// on this non-root run (a subset of Unverified; the JSON count). Skipped is
	// the number of distinct checks they belong to, what the user is told. They
	// are shown but do not floor the verdict: see models.Insight.NeedsRoot.
	NeedsRoot, Skipped int
}

// Verdict derives the overall verdict. The rule is the JSON verdict's: the
// worst of CRIT/WARN wins; INFO never raises it; but a run with any errored
// collector or Unverified insight is floored at WARN, never reported OK. The
// floor never outranks a real CRIT. An Unverified insight that is NeedsRoot (a
// non-root run could not read a root-only source) is reported but does not
// floor: a stock distro run without sudo would otherwise never be OK. Any other
// Unverified insight, and every errored collector, still does. results may be nil where only insights are
// at hand (a collector error always yields an Unverified INFO insight, see
// analysis.ApplyThresholds, so the floor still holds).
func Verdict(results []runner.Result, insights []models.Insight) VerdictInfo {
	var v VerdictInfo
	notRun := map[string]struct{}{}
	skipped := map[string]struct{}{}
	for _, ins := range insights {
		switch ins.Level {
		case "CRIT":
			v.Crit++
		case "WARN":
			v.Warn++
		case "INFO":
			v.Info++
		}
		switch {
		case ins.Unverified && ins.NeedsRoot:
			v.Unverified++
			v.NeedsRoot++
			skipped[ins.Check] = struct{}{}
		case ins.Unverified:
			v.Unverified++
			notRun[ins.Check] = struct{}{}
		}
	}
	for _, r := range results {
		if r.Err != nil {
			v.Errored++
			notRun[r.Name] = struct{}{}
		}
	}
	v.NotRun = len(notRun)
	v.Skipped = len(skipped)
	v.Level = levelFromCounts(v.Crit, v.Warn, v.Errored+v.Unverified-v.NeedsRoot)
	return v
}

func levelFromCounts(crit, warn, couldNotRun int) string {
	switch {
	case crit > 0:
		return "CRIT"
	case warn > 0, couldNotRun > 0:
		return "WARN"
	default:
		return "OK"
	}
}

// SnapshotVerdict is Verdict for a stored baseline snapshot, which keeps each
// check's status and Unverified flag but not the insight list.
func SnapshotVerdict(snap *baseline.Snapshot) VerdictInfo {
	var v VerdictInfo
	if snap == nil {
		v.Level = "OK"
		return v
	}
	for _, c := range snap.Checks {
		switch c.Status {
		case "CRIT":
			v.Crit++
		case "WARN":
			v.Warn++
		case "INFO":
			v.Info++
		}
		switch {
		case c.Unverified && c.NeedsRoot:
			v.Unverified++
			v.NeedsRoot++
			v.Skipped++
		case c.Unverified:
			v.Unverified++
			v.NotRun++
		}
	}
	v.Level = levelFromCounts(v.Crit, v.Warn, v.Unverified-v.NeedsRoot)
	return v
}

// Floored reports that the level is WARN only because checks could not run —
// there is no actual WARN or CRIT finding. This is the case every output must
// word as "not fully verified" instead of healthy.
func (v VerdictInfo) Floored() bool {
	return v.Level == "WARN" && v.Warn == 0 && v.Crit == 0
}

// Clean reports a verdict that may be worded as healthy: nothing found and
// nothing skipped.
func (v VerdictInfo) Clean() bool { return v.Level == "OK" && v.NeedsRoot == 0 }

// SkippedOnly reports an OK verdict that skipped root-only checks on a non-root
// run. It is OK for the exit code, but every output must say what was skipped
// and never word it as healthy / all checks passed.
func (v VerdictInfo) SkippedOnly() bool { return v.Level == "OK" && v.NeedsRoot > 0 }

// skippedPhrase is the visible skip line every output shares:
// "needs root: 1 check skipped — re-run with sudo".
func (v VerdictInfo) skippedPhrase() string {
	if v.Skipped == 1 {
		return "needs root: 1 check skipped — re-run with sudo"
	}
	return fmt.Sprintf("needs root: %d checks skipped — re-run with sudo", v.Skipped)
}

// ExitCode maps the level to the process exit code: 0 OK, 1 WARN, 2 CRIT.
func (v VerdictInfo) ExitCode() int {
	switch v.Level {
	case "CRIT":
		return 2
	case "WARN":
		return 1
	case "OK", "INFO": // Level is the closed OK|WARN|CRIT enum; INFO listed so no level folds silently into OK
		return 0
	}
	return 0
}

// couldNotRun is the count phrase every output shares: "1 check could not
// run" / "4 checks could not run".
func (v VerdictInfo) couldNotRun() string {
	if v.NotRun == 1 {
		return "1 check could not run"
	}
	return fmt.Sprintf("%d checks could not run", v.NotRun)
}

// TerminalBanner is the one-line summary the terminal prints when there is no
// WARN/CRIT finding to print instead. plain selects the no-emoji, no-colour
// spelling. It returns "" when the level is WARN/CRIT with real findings (the
// findings themselves are the summary).
func (v VerdictInfo) TerminalBanner(plain bool, timing string) string {
	switch {
	case v.Clean() && plain:
		return fmt.Sprintf("OK: All checks passed%s", timing)
	case v.Clean():
		return StyleOK.Render(fmt.Sprintf("✅ System healthy. Checks passed%s", timing))
	case v.Floored() && plain:
		return fmt.Sprintf("WARN: Not fully verified: %s — see INFO below%s", v.couldNotRun(), timing)
	case v.Floored():
		return StyleWarn.Render(fmt.Sprintf("⚠ Not fully verified: %s — see INFO below%s", v.couldNotRun(), timing))
	case v.SkippedOnly() && plain:
		return fmt.Sprintf("OK: No findings; %s%s", v.skippedPhrase(), timing)
	case v.SkippedOnly():
		return StyleOK.Render(fmt.Sprintf("✅ No findings; %s%s", v.skippedPhrase(), timing))
	default:
		return ""
	}
}

// SubcommandSummary is the closing line of a one-collector subcommand (dsd cpu,
// disk, docker, ...). level is "ok" for a clean run and "warn" otherwise; the
// caller picks the icon and style. A subcommand prints this only when its own
// per-section concern count is zero, so the WARN/CRIT branch is the findings
// its section checks do not count (insights the shared heuristics raise).
func (v VerdictInfo) SubcommandSummary(subject string) (level, text string) {
	switch {
	case v.Clean():
		return "ok", subject + " healthy. Checks passed"
	case v.Floored():
		return "warn", fmt.Sprintf("%s: Not fully verified: %s — re-run with sudo / see the INFO lines above", subject, v.couldNotRun())
	case v.SkippedOnly():
		return "ok", fmt.Sprintf("%s: no findings; %s", subject, v.skippedPhrase())
	default:
		return "warn", fmt.Sprintf("%s: %d critical, %d warning finding(s) — see above", subject, v.Crit, v.Warn)
	}
}

// MarkdownSummary is the --report Summary paragraph for the OK and floored
// levels ("" otherwise: the report writes its own CRIT/WARN count lines).
func (v VerdictInfo) MarkdownSummary() string {
	switch {
	case v.Clean():
		return "✅ **All checks passed** — system is healthy.\n\n"
	case v.Floored():
		return fmt.Sprintf("⚠️  **Not fully verified** — %s; see Issues below.\n\n", v.couldNotRun())
	case v.SkippedOnly():
		return fmt.Sprintf("✅ **No findings** — %s.\n\n", v.skippedPhrase())
	default:
		return ""
	}
}

// HTMLVerdict is the --report-html verdict badge: label, CSS class and text.
func (v VerdictInfo) HTMLVerdict() (label, class, text string) {
	switch {
	case v.Crit > 0:
		return "CRITICAL", "crit", fmt.Sprintf("%d critical issue(s) require immediate attention.", v.Crit)
	case v.Warn > 0:
		return "WARNING", "warn", fmt.Sprintf("%d warning(s) found — review recommended.", v.Warn)
	case v.Floored():
		return "NOT VERIFIED", "warn", fmt.Sprintf("%s — see the issues below for which.", v.couldNotRun())
	case v.SkippedOnly():
		return "NO FINDINGS", "ok", v.skippedPhrase() + "."
	default:
		return "HEALTHY", "ok", "All checks passed — system is healthy."
	}
}

// ShareLine is the `Verdict:` line of the plain-text share output.
func (v VerdictInfo) ShareLine() string {
	switch {
	case v.Crit > 0:
		return fmt.Sprintf("Verdict: CRIT — %d critical, %d warning", v.Crit, v.Warn)
	case v.Warn > 0:
		return fmt.Sprintf("Verdict: WARN — %d warning", v.Warn)
	case v.Floored():
		return fmt.Sprintf("Verdict: WARN — not fully verified: %s", v.couldNotRun())
	case v.SkippedOnly():
		return "Verdict: OK — no findings; " + v.skippedPhrase()
	default:
		return "Verdict: OK — all checks passed"
	}
}

// TopCatchNone is the "Top catch: none" tail: it may say how many checks
// passed only when every check could be verified.
func (v VerdictInfo) TopCatchNone(total int) string {
	if v.Floored() {
		return fmt.Sprintf("none — no finding, but %s.", v.couldNotRun())
	}
	if v.SkippedOnly() {
		return "none — no finding; " + v.skippedPhrase() + "."
	}
	return fmt.Sprintf("none — %d checks passed.", total)
}

// NagiosOK is the monitoring-plugin text for a clean run.
func (v VerdictInfo) NagiosOK() string {
	if v.SkippedOnly() {
		return "DASHDIAG OK - no findings; " + v.skippedPhrase()
	}
	return "DASHDIAG OK - all checks passed"
}

// StoryClean is the single-point story's sentence when nothing is WARN/CRIT.
func (v VerdictInfo) StoryClean(total int) string {
	if v.Floored() {
		return fmt.Sprintf("not fully verified — %s (run dsd health to see which).", v.couldNotRun())
	}
	if v.SkippedOnly() {
		return "no findings; " + v.skippedPhrase() + "."
	}
	return fmt.Sprintf("all %d checks passed.", total)
}

// StoryPeriodLine is the history story's closing line when no check changed
// status and none is WARN/CRIT in the latest snapshot.
func (v VerdictInfo) StoryPeriodLine() string {
	if v.Floored() {
		return fmt.Sprintf("No check changed status, but in the latest run %s — run dsd health to see which.", v.couldNotRun())
	}
	if v.SkippedOnly() {
		return "No check changed status; in the latest run " + v.skippedPhrase() + "."
	}
	return "All checks remained healthy throughout this period."
}

// StoryCurrentLine is the history story's closing line after status changes
// when the latest snapshot has no WARN/CRIT.
func (v VerdictInfo) StoryCurrentLine() string {
	if v.Floored() {
		return fmt.Sprintf("No check is WARN or CRIT now, but in the latest run %s — run dsd health to see which.", v.couldNotRun())
	}
	if v.SkippedOnly() {
		return "No check is WARN or CRIT now; in the latest run " + v.skippedPhrase() + "."
	}
	return "All checks currently healthy."
}

// Severity is the Prometheus gauge value: 0 OK, 1 WARN, 2 CRIT.
func (v VerdictInfo) Severity() int { return v.ExitCode() }

// HistoryEntry builds the record `dsd health --persist` appends to the history
// store. The verdict uses the closed vocabulary store.Entry documents
// (OK|WARN|CRIT): a run that could not verify itself is recorded as WARN, the
// same value the JSON verdict carries.
func HistoryEntry(snap *baseline.Snapshot, results []runner.Result, insights []models.Insight) store.Entry {
	checks := make(map[string]string, len(snap.Checks))
	for _, c := range snap.Checks {
		checks[c.Name] = c.Status
	}
	return store.Entry{
		Timestamp: snap.Timestamp,
		Hostname:  snap.Hostname,
		Version:   snap.Version,
		Verdict:   Verdict(results, insights).Level,
		Checks:    checks,
	}
}
