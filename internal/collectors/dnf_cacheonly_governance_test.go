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

// TestDNFCallSitesUseCacheOnly is the regression proof for the fix to GitHub
// issue #1103: `dnfWarmCache()` used to run `dnf makecache -q` once per
// process to warm dnf's local metadata cache, which (a) writes to disk
// outside dsd's own state dir and (b) can trigger a real network fetch on a
// stale cache — a genuine violation of DashDiag's read-only and
// no-collector-network invariants (see
// docs/findings/2026-09-19-FINDING-dnf-makecache-writes-and-network.md).
// dnfWarmCache and its call sites have been deleted outright; every
// remaining dnf read-query call site instead passes --cacheonly, which
// makes dnf answer only from whatever is already cached, never refreshing
// it or touching the network.
//
// This test enforces both halves of that fix mechanically, by parsing (not
// grepping — grep would also match the legitimate "dnf makecache" hint TEXT
// this codebase surfaces to an OPERATOR as manual remediation advice, e.g.
// heuristics_packages.go's noSecurityRepoHints map and cve_linux.go's
// stale-metadata messages, which must NOT be flagged) every .go source file
// under internal/collectors:
//
//  1. No identifier named dnfWarmCache exists anywhere (function removed,
//     never reintroduced under a different signature).
//  2. Every runCmd/runCmdOutput/runCmdCombined call whose target binary is
//     the literal "dnf" either is the `--version` detection probe
//     (detectPackageManager — never touches metadata) or passes
//     dnfCacheOnly/"--cacheonly" as the very next argument. This is an
//     argv-shape check, not a string-literal grep, so it cannot be fooled by
//     "makecache" appearing in a comment or an operator-facing hint string.
//
// If a future change adds a new dnf call site, this test fails closed
// unless that site also threads --cacheonly through — the same "fails
// closed on an unreviewed change" shape as this repo's other governance
// tests (parsefloat_governance_test.go, parallel_mutation_governance_test.go).
func TestDNFCallSitesUseCacheOnly(t *testing.T) {
	root := repoRootForGovernanceTest(t)
	dir := filepath.Join(root, "internal", "collectors")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var warmCacheSites []string
	var badCacheOnlySites []string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && ident.Name == "dnfWarmCache" {
				warmCacheSites = append(warmCacheSites,
					fmt.Sprintf("%s:%d", e.Name(), fset.Position(ident.Pos()).Line))
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fnIdent, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if fnIdent.Name != "runCmd" && fnIdent.Name != "runCmdOutput" && fnIdent.Name != "runCmdCombined" {
				return true
			}
			// Signature is (ctx, name, args...) — args[0]=ctx, args[1]=name.
			if len(call.Args) < 2 {
				return true
			}
			if !isStringLit(call.Args[1], "dnf") {
				return true
			}
			if len(call.Args) < 3 {
				badCacheOnlySites = append(badCacheOnlySites,
					fmt.Sprintf("%s:%d — dnf call with no trailing args at all", e.Name(), fset.Position(call.Pos()).Line))
				return true
			}
			next := call.Args[2]
			switch {
			case isStringLit(next, "--version") || isIdent(next, "pkgFlagVersion"):
				// detectPackageManager's version probe — never touches metadata.
			case isStringLit(next, "--cacheonly") || isIdent(next, "dnfCacheOnly"):
				// read-only, never refreshes, never touches the network.
			default:
				badCacheOnlySites = append(badCacheOnlySites,
					fmt.Sprintf("%s:%d — dnf call site's first argument is neither --cacheonly/dnfCacheOnly nor --version/pkgFlagVersion",
						e.Name(), fset.Position(call.Pos()).Line))
			}
			return true
		})
	}

	sort.Strings(warmCacheSites)
	sort.Strings(badCacheOnlySites)

	if len(warmCacheSites) > 0 {
		t.Errorf("dnfWarmCache must not exist anywhere in internal/collectors (issue #1103) — found references at:\n  %s",
			strings.Join(warmCacheSites, "\n  "))
	}
	if len(badCacheOnlySites) > 0 {
		t.Errorf("dnf call site(s) not using --cacheonly (issue #1103 — every dnf read-query must answer only from the "+
			"existing local cache, never refresh it or touch the network):\n  %s", strings.Join(badCacheOnlySites, "\n  "))
	}
}

// isStringLit reports whether e is a string literal with the given value.
func isStringLit(e ast.Expr, want string) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	v, err := stringLitValue(lit)
	return err == nil && v == want
}

// isIdent reports whether e is a bare identifier with the given name.
func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// stringLitValue unquotes a Go string literal's token text.
func stringLitValue(lit *ast.BasicLit) (string, error) {
	if len(lit.Value) < 2 {
		return "", fmt.Errorf("malformed string literal %q", lit.Value)
	}
	return lit.Value[1 : len(lit.Value)-1], nil
}
