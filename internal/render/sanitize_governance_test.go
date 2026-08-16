package render

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestEveryRendererFunctionSanitizesInsightText is a completeness tripwire,
// same idiom as internal/models/falseok_signal_registry_test.go and
// status_switch_governance_test.go in this package: it does not test
// behaviour, it tests that a class of bug cannot silently reappear. Like
// those, it is a fingerprint, not a correctness proof (see this file's
// Limitation note below).
//
// The bug class this closes (internal-analysis-04-05 and 15 other findings,
// see VERIFICATION-2026-08.md gap A): internal/render/report_text.go read
// models.Insight.Message/.Hints — attacker-influenced text from process/comm
// names, journal lines, cert fields, or a replayed capture bundle (dsd
// decode) — and wrote it straight to the terminal with zero escape-sequence
// stripping, while health.go/postmortem.go/report.go/watchdiff.go/story.go
// all route the same fields through output.SanitizeControl first. The same
// sweep also caught a second, previously-untagged instance of the identical
// gap: health.go's PrintAllMock (the `dsd mock` renderer) never got the
// SanitizeControl call its sibling printRow (the real `dsd health` renderer,
// same file) has — see the git history for this test's addition.
//
// Fingerprint: any function in this package whose body reads models.Insight's
// Message or Hints field (matched by selector name, so it also catches
// `for _, h := range x.Hints`, not just direct print-call arguments) must
// also call a recognized sanitizer somewhere in its body — output.
// SanitizeControl, html.EscapeString (the html/template-adjacent renderers'
// equivalent), or the local sanitizeHints wrapper. A function that touches
// Message/Hints without calling one of those is presumed to leak unsanitized
// text to its sink; add a sanitizeGovernanceExemptions entry with a reason
// if that presumption is wrong (e.g. the sink escapes by construction, like
// encoding/json or html/template auto-escaping on Execute).
//
// Limitation (deliberate — see comment above): granularity is per-FUNCTION,
// not per-statement. A function that already calls the sanitizer once (e.g.
// for Hostname) would NOT be flagged if a second, later statement in the
// same function read Message/Hints without its own guard — the earlier call
// satisfies the whole-function check. Statement-level tracking was tried and
// reverted: it false-positived on the extremely common "extract the field
// into a local now, sanitize it at the print call several statements later"
// idiom (health.go's printRow, postmortem.go's RenderPostMortem both do
// this), because the guard call and the field read land in different
// top-level statements by construction. Closing that gap needs real
// data-flow/taint tracking, not a fingerprint test — out of scope here.
func TestEveryRendererFunctionSanitizesInsightText(t *testing.T) {
	// Resolve this package's directory via this test file's own path
	// (runtime.Caller), not os.Getwd() — that's only the package directory
	// under `go test`, not when the compiled test binary is run directly
	// from another working directory (see repoRootForStatusSwitchGovernance).
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to resolve this test file's path")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var violations []string
	scannedFuncs := 0
	guardedFuncs := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			scannedFuncs++

			hasRisky := false
			hasGuard := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch expr := n.(type) {
				case *ast.SelectorExpr:
					if expr.Sel.Name == "Message" || expr.Sel.Name == "Hints" {
						hasRisky = true
					}
				case *ast.CallExpr:
					switch fun := expr.Fun.(type) {
					case *ast.SelectorExpr:
						if fun.Sel.Name == "SanitizeControl" || fun.Sel.Name == "EscapeString" {
							hasGuard = true
						}
					case *ast.Ident:
						if fun.Name == "sanitizeHints" {
							hasGuard = true
						}
					}
				}
				return true
			})

			if !hasRisky {
				continue
			}
			if hasGuard {
				guardedFuncs++
				continue
			}

			site := name + ":" + fn.Name.Name
			if reason, exempted := sanitizeGovernanceExemptions[site]; exempted {
				t.Logf("exempted %s: %s", site, reason)
				continue
			}
			violations = append(violations, site)
		}
	}

	if scannedFuncs < 10 {
		t.Fatalf("only scanned %d functions in %s — the walk is broken, this test would silently police nothing", scannedFuncs, dir)
	}
	if guardedFuncs == 0 {
		t.Fatalf("found zero functions that both touch Message/Hints and sanitize them — the guard detector itself is broken (expected health.go/postmortem.go/report.go/report_text.go/watchdiff.go/story.go to count)")
	}

	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("%d function(s) read Insight.Message/.Hints without sanitizing:\n  %s\n\n"+
			"These fields carry attacker-influenced text (process names, log lines, cert "+
			"fields, replayed capture data) that must not reach a terminal or HTML sink "+
			"unescaped. Wrap with output.SanitizeControl (plain text) or html.EscapeString "+
			"(HTML), or add a sanitizeGovernanceExemptions entry in this file with a stated "+
			"reason if the sink already escapes by construction. (Completeness tripwire — "+
			"see this file's doc comment.)",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// sanitizeGovernanceExemptions lists "file.go:FuncName" sites explicitly
// allowed to read Message/Hints without a SanitizeControl/EscapeString/
// sanitizeHints call anywhere in their own body, each with the reason it's
// safe. A reason is required — this is not a suppression list.
var sanitizeGovernanceExemptions = map[string]string{
	// buildOutput assigns ins.Message/.Hints into JSONInsight fields that are
	// later encoding/json.Marshal'd (RenderJSON/RenderYAML) — Go's encoding/json
	// escapes all control characters (including ESC, 0x1B) as \u00XX by default,
	// so raw control bytes can never reach a terminal through the JSON/YAML
	// surface. Sanitizing here would also incorrectly lossy-strip bytes from
	// the --json contract, which promises the raw collector text.
	"json.go:buildOutput": "encoding/json.Marshal escapes control characters as \\u00XX by construction",

	// insightSignature builds a tick-to-tick dedup map KEY (Check + a
	// digit-normalized Message) for InsightChanges — the return value is only
	// ever compared/looked up, never printed to any sink. There is nothing to
	// sanitize for; the actual print site in this file (PrintInsightChanges)
	// already calls output.SanitizeControl on every Insight field it prints.
	"watchdiff.go:insightSignature": "return value is an internal map key for tick dedup, never printed",
}
