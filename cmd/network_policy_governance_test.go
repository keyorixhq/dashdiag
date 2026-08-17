package cmd

import (
	"fmt"
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

// TestPersistentPreRunAppliesNetworkPolicy is a completeness tripwire for the
// bug class this fix closed: cobra's PersistentPreRun on a subcommand
// REPLACES rootCmd's rather than chaining it. rootCmd's PersistentPreRun is
// the only place --network's opt-in becomes DSD_ALLOW_NETWORK
// (applyNetworkPolicy) — any subcommand that defines its own
// PersistentPreRun (every one of them does it just to suppress the
// brand/version stderr header) silently drops that wiring unless it re-calls
// applyNetworkPolicy itself, exactly as it already has to re-call applyBrand
// (replay.go, migrate_wave.go established that pattern first).
//
// dsd mcp shipped with this exact gap for real, not just in theory: its
// PersistentPreRun blanked both calls, and mcp genuinely reaches the live,
// network-gated collector pipeline via its dsd_health/dsd_capture tools
// (runHealthOnceFn) — so `dsd mcp` ignoring `--network` was a silent
// functional bug, not a cosmetic one. capture.go's `--raw` path and
// migrate.go's `baseline` subcommand (which calls runCaptureRaw) are the same
// shape. The remaining commands checked here (diff, sanitize, mock, replay,
// migrate certify, migrate wave) are inert today — they only replay bundles
// or do no collection at all — but are wired and covered anyway so a future
// collection path added to any of them inherits the fix instead of the gap.
func TestPersistentPreRunAppliesNetworkPolicy(t *testing.T) {
	root := repoRootForNetworkPolicyGovernanceTest(t)
	dir := filepath.Join(root, "cmd")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var violations []string

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
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, val := range vs.Values {
					cl := cobraCommandLiteral(val)
					if cl == nil {
						continue
					}
					checkPersistentPreRun(cl, name, fset, &violations)
				}
			}
		}
	}

	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("%d command(s) define their own PersistentPreRun without calling "+
			"applyNetworkPolicy:\n  %s\n\n"+
			"cobra REPLACES (doesn't chain) PersistentPreRun on a subcommand that "+
			"defines its own, so rootCmd's applyNetworkPolicy(cmd) call never runs for "+
			"these — --network silently has no effect. Add applyNetworkPolicy(cmd) to "+
			"the command's PersistentPreRun, matching capture.go/mcp.go/replay.go's "+
			"existing shape. If a command's PersistentPreRun is genuinely exempt, add it "+
			"to networkPolicyGateExemptions in this file with a stated reason.",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// cobraCommandLiteral returns the *ast.CompositeLit for expr if expr is
// &cobra.Command{...}, else nil.
func cobraCommandLiteral(expr ast.Expr) *ast.CompositeLit {
	ue, ok := expr.(*ast.UnaryExpr)
	if !ok || ue.Op != token.AND {
		return nil
	}
	cl, ok := ue.X.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	sel, ok := cl.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Command" {
		return nil
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "cobra" {
		return nil
	}
	return cl
}

// checkPersistentPreRun inspects one &cobra.Command{...} literal: if it sets
// PersistentPreRun, the function literal's body must contain a call to
// applyNetworkPolicy somewhere (ast.Inspect walks nested blocks too, so this
// catches rootCmd's multi-statement body the same as a single-expression one).
func checkPersistentPreRun(cl *ast.CompositeLit, file string, fset *token.FileSet, violations *[]string) {
	var pprKV *ast.KeyValueExpr
	var useVal string
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "PersistentPreRun":
			pprKV = kv
		case "Use":
			if lit, ok := kv.Value.(*ast.BasicLit); ok {
				useVal = strings.Trim(lit.Value, "`\"")
			}
		}
	}
	if pprKV == nil {
		return // inherits rootCmd's PersistentPreRun — already calls applyNetworkPolicy
	}
	fn, ok := pprKV.Value.(*ast.FuncLit)
	if !ok || fn.Body == nil {
		return
	}

	calls := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "applyNetworkPolicy" {
			calls = true
		}
		return true
	})
	if calls {
		return
	}

	line := fset.Position(pprKV.Pos()).Line
	site := fmt.Sprintf("%s:%d", file, line)
	if _, exempted := networkPolicyGateExemptions[site]; exempted {
		return
	}
	label := useVal
	if label == "" {
		label = "(unknown Use)"
	}
	*violations = append(*violations, fmt.Sprintf("%s | command %q defines PersistentPreRun without applyNetworkPolicy(cmd)", site, label))
}

// networkPolicyGateExemptions lists "file.go:LINE" PersistentPreRun sites
// explicitly allowed to skip applyNetworkPolicy, each with the reason it's
// safe. Empty today — every command with its own PersistentPreRun calls it.
var networkPolicyGateExemptions = map[string]string{}

// repoRootForNetworkPolicyGovernanceTest mirrors
// internal/collectors/parallel_mutation_governance_test.go's
// repoRootForGovernanceTest: self-resolves the repo root from this file's own
// path via runtime.Caller rather than trusting the process CWD, which a
// t.Chdir in another test in this package could have changed.
func repoRootForNetworkPolicyGovernanceTest(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to resolve this test file's path")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod walking up from %s", thisFile)
		}
		dir = parent
	}
}
