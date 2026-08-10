package render

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestNoStatusSwitchSwallowsALevel is a repo-wide completeness tripwire, same
// idiom as internal/models/falseok_signal_registry_test.go: it does not test
// behaviour, it tests that a class of bug cannot silently reappear.
//
// The bug class (this change fixes two live instances of it): a switch over
// dsd's severity vocabulary — fingerprinted here as a switch whose case list
// includes both "CRIT" and "WARN" as string literals, the two labels no other
// Status-like vocabulary in this repo uses together (CIS uses
// models.CISPass/Fail, PVE guest state uses "paused"/"stopped", Elasticsearch
// cluster health uses "red"/"green"/"yellow") — that also has a `default:`
// clause. A `default:` on this vocabulary means "treat as OK": that's exactly
// right when the switch enumerates CRIT, WARN, and INFO explicitly and lets
// only the true OK case fall through. It's a silent false-OK the moment INFO
// is left out, because INFO is not "everything else" — it means "a collector
// errored or a value went unmeasurable," and swallowing it into the OK
// fallback is indistinguishable from a clean pass. That is precisely what
// internal/render/report.go's Check Results table and internal/render/
// html.go's buildHTMLCheckRows did before this change: a collector that
// completely failed to run rendered "✅ OK".
//
// Switches over this vocabulary with NO default clause (there are several,
// repo-wide — vote-counters and icon-pickers that intentionally no-op for
// levels they don't care about, e.g. cmd/exitcode.go, internal/render/
// json.go's JSONCounts tally) are a different, safe shape: nothing they do
// implies a positive claim for an unhandled level, so they are out of scope
// for this guard by construction (scanning for `default:` is the filter).
func TestNoStatusSwitchSwallowsALevel(t *testing.T) {
	root := repoRootForStatusSwitchGovernance(t)

	goFiles := collectNonTestGoFiles(t, root)
	if len(goFiles) < 200 { // sanity: repo has ~900 non-test .go files as of writing
		t.Fatalf("only found %d non-test .go files under %s — the walk is broken or root is wrong, "+
			"this test would silently police nothing", len(goFiles), root)
	}

	fset := token.NewFileSet()
	var violations []string
	for _, path := range goFiles {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			relPath = path
		}

		ast.Inspect(file, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || sw.Tag == nil {
				return true
			}
			sel, ok := sw.Tag.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Status" && sel.Sel.Name != "Level") {
				return true
			}

			cases := map[string]bool{}
			hasDefault := false
			for _, stmt := range sw.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				if cc.List == nil {
					hasDefault = true
					continue
				}
				for _, expr := range cc.List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if v, err := strconv.Unquote(lit.Value); err == nil {
						cases[v] = true
					}
				}
			}

			// Fingerprint: this repo's severity vocabulary, and only it, uses
			// "CRIT" and "WARN" as case labels on the same switch.
			if !cases["CRIT"] || !cases["WARN"] {
				return true
			}
			if !hasDefault {
				return true // no positive fallback claim — out of scope, see doc comment
			}
			if cases["INFO"] {
				return true // fully accounted for
			}

			site := relPath + ":" + strconv.Itoa(fset.Position(sw.Pos()).Line)
			if reason, exempted := statusSwitchDefaultExemptions[site]; exempted {
				t.Logf("exempted %s: %s", site, reason)
				return true
			}
			violations = append(violations, site)
			return true
		})
	}
	sort.Strings(violations)

	if len(violations) > 0 {
		t.Errorf("%d switch(es) over CRIT/WARN dispatch to a default (OK) fallback without an "+
			"explicit INFO case:\n  %s\n\n"+
			"INFO means 'could not verify' (a collector error or unmeasurable value), not 'everything "+
			"else' — folding it into the OK default is a silent false-OK. Add an explicit `case \"INFO\":` "+
			"branch, or if the omission is provably safe, add a statusSwitchDefaultExemptions entry in "+
			"this file with a stated reason. (Completeness tripwire — see this file's doc comment.)",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// statusSwitchDefaultExemptions lists "relative/path/to/file.go:LINE" sites
// (the switch statement's own line) explicitly allowed to fold INFO into
// their default/OK branch, each with the reason it's safe. Empty today —
// both instances this guard found (report.go's Check Results table, html.go's
// buildHTMLCheckRows) were fixed rather than exempted. Add an entry only when
// the omission is provably safe — a reason is required, this is not a
// suppression list.
var statusSwitchDefaultExemptions = map[string]string{}

// collectNonTestGoFiles walks root for production (*.go, not *_test.go)
// files, skipping the same throwaway/generated directories the parallel-
// mutation guard excludes: .scratch/ (repo scratch dir), .git/, .claude/
// (including .claude/worktrees/, full duplicate checkouts).
func collectNonTestGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".scratch", ".git", ".claude", "node_modules", "vendor", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for .go files: %v", root, err)
	}
	return files
}

// repoRootForStatusSwitchGovernance resolves the module root via this test
// file's own path (runtime.Caller), not the process working directory —
// go test's CWD is the package directory, not the repo root.
func repoRootForStatusSwitchGovernance(t *testing.T) string {
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
