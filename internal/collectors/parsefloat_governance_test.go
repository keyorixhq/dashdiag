package collectors

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestParseFloatCallSitesGuardNaNInf is a completeness tripwire for the bug
// class fixed by PRs #722/#723/#724 (2026-07-06, "fuzz-firewall-and-fix-
// parsefloat" / "guard-all-parsefloat-callsites" / "guard-pattern-b-and-
// duration-overflow"): strconv.ParseFloat treats "NaN"/"Inf"/"+Inf"/"-Inf" as
// SUCCESSFUL parses, not errors, so `v, err := strconv.ParseFloat(...); err
// == nil` alone lets a garbled/NaN/Inf value through silently.
//
// PR #723's own title was "route every discarded-error ParseFloat call
// through the shared guard" (parseFloat/parseFiniteFloat, io.go) — a
// one-time MANUAL sweep. It was never made durable by a test or lint rule,
// which is exactly why two more unguarded sites (zfs.go's parseZFSSize,
// snapper_linux.go's parseMiB — both a SECOND layer of the same problem: a
// post-parse unit multiply/cast overflowing a value that had already passed
// a raw-parse-only check) shipped and were later found live by scheduled
// fuzzing. This test is that missing durable guard, generalized past
// collectors: it walks every strconv.ParseFloat call site under internal/
// and cmd/ (a directory walk, not a hardcoded file list — a hardcoded list
// would silently exclude a new file, the same shape of gap this test exists
// to close) and requires each site's ENCLOSING FUNCTION to also reference
// math.IsNaN or math.IsInf somewhere in its body (the guard is function-
// scoped, not statement-scoped, because the established shapes in this
// codebase differ: some check inline in the same `if` condition
// (raid_linux.go), some in a separate statement right after (this fix's own
// container.go/since_deploy.go additions) — function-scoped catches both
// without over-fitting to one exact shape) — or is in the stated exemption
// list below.
//
// Not a check for the SECOND layer (post-multiply/cast overflow) — that
// requires understanding each site's specific arithmetic and downstream use,
// which isn't mechanically checkable the way "does this function mention
// IsNaN/IsInf at all" is. The two fixed bugs' seed corpus entries
// (FuzzParseZFSVdevErrors, FuzzParseMiB) are the regression guard for that
// layer instead — see internal/collectors/testdata/fuzz/.
func TestParseFloatCallSitesGuardNaNInf(t *testing.T) {
	root := repoRootForGovernanceTest(t)
	dirs := []string{
		filepath.Join(root, "internal"),
		filepath.Join(root, "cmd"),
	}

	fset := token.NewFileSet()
	var violations []string

	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}
			rel, _ := filepath.Rel(root, path)
			violations = append(violations, checkFileForUnguardedParseFloat(file, fset, rel)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}

	var real []string
	for _, v := range violations {
		site, _, found := strings.Cut(v, " | ")
		if found {
			if reason, exempted := parseFloatGateExemptions[site]; exempted {
				t.Logf("exempted %s: %s", site, reason)
				continue
			}
		}
		real = append(real, v)
	}
	sort.Strings(real)

	if len(real) > 0 {
		t.Errorf("%d strconv.ParseFloat call site(s) not guarded against NaN/Inf:\n  %s\n\n"+
			"strconv.ParseFloat(\"NaN\") and strconv.ParseFloat(\"Inf\") both return err=nil — "+
			"an err-only check silently lets a garbled value through. Either route the call "+
			"through parseFloat/parseFiniteFloat (internal/collectors/io.go, if the package can "+
			"import collectors), or add an explicit math.IsNaN(...)/math.IsInf(...) check "+
			"somewhere in the same function. If a site is genuinely safe as-is (e.g. a downstream "+
			"threshold catches NaN/Inf anyway, or the parsed value is never used), add a "+
			"parseFloatGateExemptions entry in this file with a stated, verified reason — this is "+
			"not a suppression list.",
			len(real), strings.Join(real, "\n  "))
	}
}

// checkFileForUnguardedParseFloat returns one violation string per
// unguarded strconv.ParseFloat call site in file, formatted "path:LINE | in
// funcName — reason".
func checkFileForUnguardedParseFloat(file *ast.File, fset *token.FileSet, relPath string) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var callSites []int
		hasNaNInfCheck := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch pkgIdent.Name + "." + sel.Sel.Name {
			case "strconv.ParseFloat":
				callSites = append(callSites, fset.Position(call.Pos()).Line)
			case "math.IsNaN", "math.IsInf":
				hasNaNInfCheck = true
			case "collectors.parseFloat", "collectors.parseFiniteFloat":
				// Cross-package call shape doesn't actually occur (parseFloat/
				// parseFiniteFloat are unexported), kept for completeness.
				hasNaNInfCheck = true
			}
			return true
		})
		if hasNaNInfCheck || len(callSites) == 0 {
			continue
		}
		// A bare `parseFloat(...)`/`parseFiniteFloat(...)` call (same-package,
		// unqualified — the shared-helper shape used throughout collectors)
		// also counts as guarded; it wouldn't be caught by the switch above
		// since it's an *ast.Ident call, not a *ast.SelectorExpr.
		if fileUsesSharedFloatGuard(fn.Body) {
			continue
		}
		for _, line := range callSites {
			out = append(out, fmt.Sprintf("%s:%d | in %s — raw strconv.ParseFloat, no IsNaN/IsInf check or shared-guard call found in this function",
				relPath, line, fn.Name.Name))
		}
	}
	return out
}

// fileUsesSharedFloatGuard reports whether body calls the unexported
// parseFloat/parseFiniteFloat helpers (internal/collectors/io.go) as a bare,
// same-package identifier — the shape every other collectors.go call site in
// this package already uses instead of a raw strconv.ParseFloat.
func fileUsesSharedFloatGuard(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "parseFloat" || id.Name == "parseFiniteFloat") {
			found = true
		}
		return true
	})
	return found
}

// parseFloatGateExemptions lists "path:LINE" strconv.ParseFloat call sites
// explicitly allowed to skip an in-function NaN/Inf check, each with the
// reason it's safe. These are pre-existing sites this fix's audit found and
// characterized but did not change — tracked here so the gap stays visible
// and grep-able rather than silently missed, per this project's own
// "twelve times missed a sibling" pattern. A follow-up sweep matching PRs
// #722-724's scope, not this fix, should close them.
var parseFloatGateExemptions = map[string]string{
	"internal/collectors/lvm_parse.go:153":  "parsed value is discarded — only err distinguishes a numeric field from a non-numeric one; there is no NaN/Inf to leak",
	"internal/collectors/nvme_linux.go:177": "already guarded: err==nil && k>0 && !math.IsInf(k,0) in the same condition (k>0 rejects NaN too, since all NaN comparisons are false)",
	"internal/collectors/nvme_linux.go:186": "already guarded: err==nil && !math.IsNaN(c) && !math.IsInf(c,0) in the same condition",

	"internal/collectors/network_quick.go:440":    "ping RTT parse — a NaN/Inf RTT feeds a <100ms-style WARN threshold that fails loud (not a false-OK); low realistic attacker control (local ping output)",
	"internal/collectors/network_quick.go:451":    "ping RTT parse, same shape as :440",
	"internal/collectors/cpuinfo.go:57":           "cpu MHz — display-only field, no verdict threshold reads it",
	"internal/collectors/pressure_linux.go:95":    "kernel-authored /proc/pressure/* value; a NaN PSI avg fails every WARN/CRIT threshold loud rather than false-OK",
	"internal/collectors/postgres_linux.go:145":   "lag>=0 in the same condition rejects NaN and negative; +Inf slips through but only makes the >300s WARN/CRIT threshold fire, never a false-OK",
	"internal/collectors/cpu.go:57":               "kernel-authored /proc/loadavg field 1; feeds a load-average WARN/CRIT threshold that fails loud on NaN, never false-OK",
	"internal/collectors/cpu.go:60":               "kernel-authored /proc/loadavg field 2, same shape as :57",
	"internal/collectors/cpu.go:63":               "kernel-authored /proc/loadavg field 3, same shape as :57",
	"internal/collectors/cpu.go:420":              "per-core busy%% from /proc/stat deltas; a NaN core percentage is a display-only anomaly, not a verdict input",
	"internal/collectors/thermal_linux.go:94":     "milliC parse — the caller's TempPlausible(c,ceiling) range check (analysis/temp.go) already rejects NaN/Inf before any verdict reads the value",
	"internal/collectors/thermal_linux.go:137":    "same TempPlausible downstream guard as :94",
	"internal/collectors/thermal_notlinux.go:83":  "v>0 in the same condition rejects NaN; TempPlausible (analysis/temp.go) rejects +Inf downstream before any verdict reads the value",
	"internal/collectors/thermal_notlinux.go:102": "same TempPlausible downstream guard as :83",
	"internal/collectors/thermal_notlinux.go:130": "same TempPlausible downstream guard as :83",
	"internal/collectors/logs_linux.go:243":       "kmsg lookback-window boundary; a NaN/Inf timestamp makes the window filter a no-op (extra/missing log lines), not a verdict false-OK",
	"internal/collectors/logs_linux.go:272":       "kmsg entry timestamp, same shape as :243",
	"internal/collectors/timeline_linux.go:506":   "dmesg monotonic-offset fallback (C3); a NaN/Inf offset makes ts.Before(since) unpredictable, dropping or keeping one event from the fallback-only path — a display/completeness quirk on an already-degraded (busybox/no-time-format) source, not a verdict false-OK, same shape as logs_linux.go's kmsg lookback boundary above",
	"internal/collectors/ipmi_linux.go:129":       "sensor.Value is display-only — the health verdict for this sensor comes from ipmitool's own Status string field, never from Value numerically",
}
