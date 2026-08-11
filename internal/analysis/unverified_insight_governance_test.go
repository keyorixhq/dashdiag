package analysis

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// unverifiedPhraseRe matches the phrasing this package's own heuristics use,
// throughout, to describe "we could not measure this" (permission denied,
// unreadable file, unreachable API, collector/tool error) — as opposed to a
// genuine finding. Deliberately narrow: broader words like "unreachable" on
// their own are also used by confirmed findings (a service confirmed down,
// not merely unchecked), so including them would flag too much. This regex
// is intentionally the same phrasing this file's sweep was performed with.
var unverifiedPhraseRe = regexp.MustCompile(
	`(?i)could not (be )?(read|verif|determin)|not (readable|verified)\b|\bunverified\b|\bunreadable\b`)

// unverifiedInsightExemptions lists insight() call sites whose message text
// matches unverifiedPhraseRe but are deliberately NOT unverifiedInsight() —
// they describe a CONFIRMED finding, not a measurement gap. Keyed by the
// literal (or best-effort-extracted) message text so an exemption goes stale
// — and must be revisited — the moment its wording changes, same discipline
// as guardedUnverifiedSignals in internal/models/falseok_signal_registry_test.go.
var unverifiedInsightExemptions = map[string]string{
	// SMART pending-sector counts: dsd DID read the drive's SMART data
	// successfully — "unreadable sectors" describes what the DRIVE reports
	// about itself (sectors it can no longer read), not a dsd measurement gap.
	"%s: %d pending sector(s) — unreadable sectors awaiting remap":           "heuristics_hardware.go checkDiskExtras (confirmed SMART finding, not unverified)",
	"%s has %d pending sector(s) — unreadable sectors awaiting reallocation": "heuristics_storage.go checkDiskExtras SATA path (same as above, sibling implementation)",

	// GPU "[N/A]" from nvidia-smi: a specific, confident diagnosis (card fell
	// off the bus / hardware fault), not an ambiguous "couldn't check" state —
	// re-running as root would not change nvidia-smi's answer.
	"%s metrics unreadable — nvidia-smi reported [N/A] for temperature and memory (GPU likely fallen off the bus / hardware fault)": "heuristics_hardware.go checkGPUDevice (confident hardware-fault diagnosis, not unverified)",

	// systemd-networkd config file permissions: dsd itself read the file (that
	// is how it knows the mode) — the gap is networkd's, not dsd's measurement.
	"%d systemd-networkd config file(s) not readable by networkd (need mode 0644) — silently ignored, so the network they configure may not be applied": "heuristics_networkd.go checkNetworkdConfig (confirmed permission-mode finding, dsd read the file successfully)",
}

// TestUnverifiedInsightPhrasingCoverage is a completeness tripwire, same idiom
// as internal/models/falseok_signal_registry_test.go and
// internal/collectors/parallel_mutation_governance_test.go: it does not prove
// unverifiedInsight() is used correctly, it proves a NEW insight() call whose
// message reads like "we couldn't measure this" cannot silently reappear
// without a conscious decision (convert it to unverifiedInsight(), or add a
// justified exemption above).
//
// Why this exists: the internal/baseline false-clean fix (a WARN/CRIT that
// becomes unmeasurable on a re-run must never diff as "Improved" — see
// baseline.ComputeDiff) depends entirely on every such heuristic marking its
// insight Unverified. That sweep touched ~120 call sites by hand across ~36
// files with no earlier automated check — and this test's own first run
// caught 3 real misses (heuristics_security.go checkFirewall/checkAuditd,
// heuristics_vmware.go's stat-unavailable path) that the manual sweep skipped.
// Without a guard, the same class of miss can recur silently on every future
// heuristic addition.
func TestUnverifiedInsightPhrasingCoverage(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read internal/analysis: %v", err)
	}

	fset := token.NewFileSet()
	found := map[string]string{} // message text -> "file:line" of first match
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "insight" || len(call.Args) < 3 {
				return true
			}
			msg := extractStaticString(call.Args[2])
			if msg == "" || !unverifiedPhraseRe.MatchString(msg) {
				return true
			}
			if _, seen := found[msg]; !seen {
				pos := fset.Position(call.Pos())
				found[msg] = name + ":" + strconv.Itoa(pos.Line)
			}
			return true
		})
	}

	var unregistered, stale []string
	for msg, loc := range found {
		if _, ok := unverifiedInsightExemptions[msg]; !ok {
			unregistered = append(unregistered, loc+": "+msg)
		}
	}
	for msg, note := range unverifiedInsightExemptions {
		if _, ok := found[msg]; !ok {
			stale = append(stale, msg+" ("+note+")")
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)

	if len(unregistered) > 0 {
		t.Errorf("%d insight() call(s) read like a measurement gap (\"could not verify\", \"unreadable\", etc.) but "+
			"aren't unverifiedInsight() and aren't exempted:\n  %s\n\n"+
			"Each either represents a genuine \"couldn't measure this\" state — switch it to unverifiedInsight() — "+
			"or is a confirmed finding that merely uses similar wording — add a justified entry to "+
			"unverifiedInsightExemptions explaining why. (Completeness tripwire — see this test's doc comment.)",
			len(unregistered), strings.Join(unregistered, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d exemption(s) in unverifiedInsightExemptions no longer match any insight() call (wording changed "+
			"or the call was removed/converted) — update the key or remove the entry:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// extractStaticString best-effort-extracts the literal text of a message
// expression: a plain string literal, a fmt.Sprintf(...) format string, or a
// "literal" + variable concatenation (literal parts only — the variable
// contributes nothing, which is fine since the trigger phrasing this test
// looks for lives in the static prose, never in the interpolated value).
// Returns "" when the expression isn't statically inspectable at all (a bare
// variable/field) — those calls are invisible to this test by design; it is
// a best-effort tripwire, not a full data-flow analysis.
func extractStaticString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			if s, err := strconv.Unquote(v.Value); err == nil {
				return s
			}
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			return extractStaticString(v.X) + extractStaticString(v.Y)
		}
	case *ast.CallExpr:
		sel, ok := v.Fun.(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "Sprintf" && len(v.Args) > 0 {
			return extractStaticString(v.Args[0])
		}
	}
	return ""
}
