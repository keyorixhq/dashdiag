package render

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// This file is the ONE place a check's coverage (checked / not checked / not
// applicable) is derived, next to Verdict. DD-COVERAGE-1: status alone cannot
// tell "looked, fine" from "did not look" from "nothing to look at", so every
// output asks Coverage instead of re-deriving it. TestGuardC_* fails if an output
// does, and if a collector cannot resolve to exactly one coverage value.
//
// The rule, applied everywhere:
//
//   - A collector that returned an error (or timed out, or panicked) is
//     not_checked, reason timeout / unreadable / collector_error.
//   - A collector that returned nothing (nil data) or reports itself absent
//     (Available=false) with no insight is not_applicable (not_supported_platform
//     / not_present). This is exactly the set checks[] has always omitted.
//   - A collector that is absent but still carries an Unverified insight (the
//     tool is there, the cluster is not reachable) is not_checked: something said
//     it could not look.
//   - Any other collector is checked. If some of what it checks could not be
//     read (an Unverified insight owned by it), it stays checked and lists those
//     in not_checked_subchecks: the rest of it did run. "Nothing meaningful ran"
//     is therefore never inferred from insights, only from an error or an absent
//     collector, which the collector itself reports.
//
// The verdict is untouched: Verdict still floors on every not_checked item
// except needs_root ones (TestCoverageMatchesVerdict pins the two together).

// Coverage derives the coverage of one run from the collector results and the
// insights analysis produced from them.
func Coverage(results []runner.Result, insights []models.Insight) models.CoverageSummary {
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Name)
	}

	// Every insight is owned by at most one result, so an Unverified one is
	// counted once.
	type perCheck struct {
		insights   int
		unverified []models.SubCheck
	}
	owned := map[string]*perCheck{}
	var orphans []models.SubCheck
	for _, ins := range insights {
		owner := insightOwner(ins.Check, names)
		if owner == "" {
			if ins.Unverified {
				orphans = append(orphans, subCheckOf(ins))
			}
			continue
		}
		pc := owned[owner]
		if pc == nil {
			pc = &perCheck{}
			owned[owner] = pc
		}
		pc.insights++
		if ins.Unverified {
			pc.unverified = append(pc.unverified, subCheckOf(ins))
		}
	}

	var sum models.CoverageSummary
	seenItem := map[string]string{} // check name -> reason of the item already counted
	addItem := func(name, reason string) {
		prev, ok := seenItem[name]
		switch {
		case !ok:
			seenItem[name] = reason
			sum.NotChecked++
			addReason(&sum, reason)
		case prev == models.ReasonNeedsRoot && reason != models.ReasonNeedsRoot:
			// The same check is both root-only and otherwise unverified: the
			// worse one (it floors the verdict) is what the user is told.
			addReasonDelta(&sum, prev, -1)
			addReason(&sum, reason)
			seenItem[name] = reason
		}
	}

	seenResult := map[string]bool{}
	for _, r := range results {
		if seenResult[r.Name] {
			continue // a name appears once, as in checks[]
		}
		seenResult[r.Name] = true
		pc := owned[r.Name]
		if pc == nil {
			pc = &perCheck{}
		}
		cc := models.CheckCoverage{Name: r.Name, Coverage: models.CoverageChecked}
		switch {
		case r.Err != nil:
			cc.Coverage = models.CoverageNotChecked
			cc.Reason = errReason(r.Err)
			addItem(r.Name, cc.Reason)
		case r.Data == nil || !runner.IsAvailable(r.Data):
			switch {
			case len(pc.unverified) > 0:
				cc.Coverage = models.CoverageNotChecked
				cc.Reason = worstReason(pc.unverified)
				addItem(r.Name, cc.Reason)
				cc.NotCheckedSubchecks = pc.unverified
				for _, sc := range pc.unverified {
					addItem(sc.Check, sc.Reason)
				}
			case pc.insights > 0:
				// An insight about an absent collector is an actionable finding.
			case r.Data == nil:
				cc.Coverage = models.CoverageNotApplicable
				cc.Reason = models.ReasonNotSupportedPlatform
			default:
				cc.Coverage = models.CoverageNotApplicable
				cc.Reason = models.ReasonNotPresent
			}
		default:
			for _, sc := range pc.unverified {
				cc.NotCheckedSubchecks = append(cc.NotCheckedSubchecks, sc)
				addItem(sc.Check, sc.Reason)
			}
			if len(cc.NotCheckedSubchecks) > 0 {
				sum.Partial++
			}
		}
		switch cc.Coverage {
		case models.CoverageChecked:
			sum.Checked++
		case models.CoverageNotApplicable:
			sum.NotApplicable++
		}
		sum.Checks = append(sum.Checks, cc)
	}
	// An Unverified insight no collector result owns still says something was
	// not looked at (the verdict floors on it): keep it visible and counted.
	for _, sc := range orphans {
		addItem(sc.Check, sc.Reason)
		sum.Checks = append(sum.Checks, models.CheckCoverage{
			Name: sc.Check, Coverage: models.CoverageNotChecked, Reason: sc.Reason,
		})
	}
	sort.SliceStable(sum.Checks, func(i, j int) bool { return sum.Checks[i].Name < sum.Checks[j].Name })
	return sum
}

func addReason(s *models.CoverageSummary, reason string) { addReasonDelta(s, reason, 1) }

func addReasonDelta(s *models.CoverageSummary, reason string, d int) {
	if s.Reasons == nil {
		s.Reasons = map[string]int{}
	}
	s.Reasons[reason] += d
	if s.Reasons[reason] == 0 {
		delete(s.Reasons, reason)
	}
}

func subCheckOf(ins models.Insight) models.SubCheck {
	reason := models.ReasonUnverified
	if ins.NeedsRoot {
		reason = models.ReasonNeedsRoot
	}
	// The message is attacker-influenced text (replayed captures, log lines).
	return models.SubCheck{Check: ins.Check, Reason: reason, Message: output.SanitizeControl(ins.Message)}
}

// worstReason is the reason of the sub-checks as a whole: any that is not
// root-only wins, as it is the one that floors the verdict.
func worstReason(subs []models.SubCheck) string {
	for _, s := range subs {
		if s.Reason != models.ReasonNeedsRoot {
			return s.Reason
		}
	}
	return models.ReasonNeedsRoot
}

// insightOwner returns the result name an insight's Check belongs to: the exact
// name, else the longest name it is subsystem-qualified by ("Network/DNS",
// "Disk /var"), the same matching checks[] uses. "" when no result owns it.
func insightOwner(check string, names []string) string {
	best := ""
	for _, n := range names {
		if n == check {
			return n
		}
		if (strings.HasPrefix(check, n+"/") || strings.HasPrefix(check, n+" ")) && len(n) > len(best) {
			best = n
		}
	}
	return best
}

// errReason classifies a collector error. A needs_root reason is never derived
// here: Verdict floors an errored collector, so it is not a root-only skip.
func errReason(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		strings.Contains(msg, "timed out"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return models.ReasonTimeout
	case errors.Is(err, fs.ErrPermission),
		strings.Contains(msg, "permission denied"), strings.Contains(msg, "operation not permitted"):
		return models.ReasonUnreadable
	}
	return models.ReasonCollectorError
}

// CoverageAction is what the user can do about a not-checked reason.
func CoverageAction(reason string) string {
	switch reason {
	case models.ReasonNeedsRoot:
		return "re-run with sudo"
	case models.ReasonTimeout:
		return "re-run; if it repeats, run this check on its own"
	case models.ReasonUnreadable:
		return "check file permissions or re-run with sudo"
	case models.ReasonCollectorError:
		return "run this check on its own for the error"
	case models.ReasonUnverified:
		return "see the INFO line for what could not be read"
	}
	return ""
}

// NotCheckedItem is one thing that was not looked at, flattened for display.
type NotCheckedItem struct {
	Check, Reason, Message string
}

// Action is what to do about it.
func (i NotCheckedItem) Action() string { return CoverageAction(i.Reason) }

// NotCheckedItems lists what was not looked at, whole checks and sub-checks, in
// name order, one per distinct check name (the count CoverageSummary.NotChecked).
func NotCheckedItems(s *models.CoverageSummary) []NotCheckedItem {
	if s == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []NotCheckedItem
	add := func(it NotCheckedItem) {
		if !seen[it.Check] {
			seen[it.Check] = true
			out = append(out, it)
		}
	}
	for _, c := range s.Checks {
		if c.Coverage == models.CoverageNotChecked {
			add(NotCheckedItem{Check: c.Name, Reason: c.Reason})
		}
		for _, sc := range c.NotCheckedSubchecks {
			add(NotCheckedItem{Check: sc.Check, Reason: sc.Reason, Message: output.SanitizeControl(sc.Message)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Check < out[j].Check })
	return out
}

// NotApplicableChecks lists the collectors with nothing to check on this host.
func NotApplicableChecks(s *models.CoverageSummary) []models.CheckCoverage {
	if s == nil {
		return nil
	}
	var out []models.CheckCoverage
	for _, c := range s.Checks {
		if c.Coverage == models.CoverageNotApplicable {
			out = append(out, c)
		}
	}
	return out
}

// reasonCounts renders "needs root: 2, timeout: 1" (most first, then by name).
func reasonCounts(s *models.CoverageSummary) string {
	type rc struct {
		reason string
		n      int
	}
	var rcs []rc
	for r, n := range s.Reasons {
		rcs = append(rcs, rc{r, n})
	}
	sort.Slice(rcs, func(i, j int) bool {
		if rcs[i].n != rcs[j].n {
			return rcs[i].n > rcs[j].n
		}
		return rcs[i].reason < rcs[j].reason
	})
	parts := make([]string, len(rcs))
	for i, x := range rcs {
		parts[i] = fmt.Sprintf("%s: %d", strings.ReplaceAll(x.reason, "_", " "), x.n)
	}
	return strings.Join(parts, ", ")
}

// CoverageLine is the summary line every human output shares:
// "12 checked · 3 not checked (needs root: 2, timeout: 1) · 31 not applicable".
// A zero part is left out, except "checked".
func CoverageLine(s *models.CoverageSummary) string {
	if s == nil {
		return ""
	}
	parts := []string{fmt.Sprintf("%d checked", s.Checked)}
	if s.NotChecked > 0 {
		parts = append(parts, fmt.Sprintf("%d not checked (%s)", s.NotChecked, reasonCounts(s)))
	}
	if s.NotApplicable > 0 {
		parts = append(parts, fmt.Sprintf("%d not applicable", s.NotApplicable))
	}
	return strings.Join(parts, " · ")
}
