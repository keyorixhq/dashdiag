package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestNoBareOSWriteFileInCmdOrRender is a completeness tripwire for the
// hardened-write-helper bug class, same idiom as this package's own
// TestPersistentPreRunAppliesNetworkPolicy and internal/render's
// TestEveryRendererFunctionSanitizesInsightText: it does not test behaviour,
// it tests that a class of bug cannot silently reappear.
//
// os.WriteFile opens with O_CREATE|O_TRUNC and no O_NOFOLLOW, so it follows
// an existing symlink at its destination rather than refusing it. For a
// PREDICTABLE, FIXED destination path (a hostname-derived report filename, a
// fixed hook script location, an --out path) written from a
// shared/multi-tenant working directory, another local user can pre-plant a
// symlink there and have the write silently clobber whatever it points at.
// This codebase has a hardened alternative for every such site already:
// cmd/writefile.go's writeFileNoFollow, cmd/root.go's createOutFile,
// internal/render/writefile.go's writeReportFileNoFollow,
// internal/source/persist.go's writeBlobNoFollow — all O_NOFOLLOW under the
// hood. The problem was never inventing the fix; it was applying it
// everywhere the same shape of write occurs. Found 2026-09 (adversarial code
// review): six call sites in cmd/ and internal/render/ used plain
// os.WriteFile despite a sibling in the SAME FILE, doing the SAME kind of
// write, already routing through the hardened helper —
// installGitHubActions next to installGitHook/installPreDeploy,
// GenerateReport/GenerateHTMLReport next to fleet_html.go/wave_html.go's
// identical pattern, --out in cmd/inventory.go unlike cmd/root.go's --out.
// Fifth instance in two weeks of "fix invented once, applied
// inconsistently" in this repo, after the hardcoded fuzz target lists, the
// shellcheck file list, and the `< <(...)` process substitutions — see
// CONTRIBUTING.md's "Guards must fail loudly" section for the shape of
// that pattern, and DEFECT-CLASSES.md for this one.
//
// Scope is deliberately narrow: cmd/ and internal/render/'s own top-level
// .go files (not subdirectories, not _test.go files) — the two directories
// item 3's review actually swept. A bare os.WriteFile anywhere else in the
// module is out of scope for this test (most of them write to a private
// os.MkdirTemp dir or another non-predictable path, where this class of bug
// doesn't apply).
func TestNoBareOSWriteFileInCmdOrRender(t *testing.T) {
	root := repoRootForWriteFileGovernanceTest(t)
	dirs := []string{filepath.Join(root, "cmd"), filepath.Join(root, "internal", "render")}

	fset := token.NewFileSet()
	var violations []string
	scannedFiles := 0

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}

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
			scannedFiles++

			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "WriteFile" {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "os" {
					return true
				}

				pos := fset.Position(call.Pos())
				site := filepath.Base(pos.Filename) + ":" + strconv.Itoa(pos.Line)
				if reason, exempted := writeFileGovernanceExemptions[site]; exempted {
					t.Logf("exempted %s: %s", site, reason)
					return true
				}
				violations = append(violations, site)
				return true
			})
		}
	}

	if scannedFiles < 10 {
		t.Fatalf("only scanned %d files across %v — the walk is broken, this test would silently police nothing", scannedFiles, dirs)
	}

	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("%d bare os.WriteFile call(s) in cmd/ or internal/render/ outside the exemption list:\n  %s\n\n"+
			"os.WriteFile follows an existing symlink at its destination — use writeFileNoFollow "+
			"(cmd/writefile.go), createOutFile (cmd/root.go), or writeReportFileNoFollow "+
			"(internal/render/writefile.go) instead, or add a writeFileGovernanceExemptions entry "+
			"in this file with a stated reason if the destination genuinely isn't a "+
			"predictable/shared-directory path (completeness tripwire — see this file's doc comment).",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// writeFileGovernanceExemptions lists "file.go:line" sites explicitly
// allowed to call os.WriteFile directly, each with the reason it's safe. A
// reason is required — this is not a suppression list.
var writeFileGovernanceExemptions = map[string]string{
	// installSystemdTimer writes /etc/systemd/system/dsd-health.{timer,service}
	// — fixed, root-owned paths, not a CWD-relative or shared-working-directory
	// location. An unprivileged local attacker cannot plant a symlink there in
	// the first place (same reasoning SECURITY.md and BACKLOG.md's
	// refuse_symlinked_prefix() entry already apply to the default,
	// root-owned --prefix). Opt-in, requires root/sudo; out of scope for the
	// symlink-hardening sweep that added this test.
	"hook.go:264": "writes /etc/systemd/system/dsd-health.timer, a fixed root-owned path an unprivileged attacker can't symlink",
	"hook.go:269": "writes /etc/systemd/system/dsd-health.service, a fixed root-owned path an unprivileged attacker can't symlink",
}

// repoRootForWriteFileGovernanceTest mirrors this package's own
// repoRootForNetworkPolicyGovernanceTest (and internal/collectors',
// internal/render's siblings): self-resolves the repo root from this file's
// own path via runtime.Caller rather than trusting the process CWD, which a
// t.Chdir in another test in this package could have changed.
func repoRootForWriteFileGovernanceTest(t *testing.T) string {
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
