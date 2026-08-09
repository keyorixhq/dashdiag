package collectors

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestNoGlobalMutationInParallelTests is a repo-wide completeness tripwire,
// same idiom as internal/models/falseok_signal_registry_test.go: it does not
// test behaviour, it tests that a class of bug cannot silently reappear.
//
// The bug class: a test mutates process-global state (CWD, an env var) or a
// package-level var while t.Parallel() is in effect anywhere in its own test
// tree — itself, an ancestor, or a t.Run subtest. All three real instances
// found in this repo (render/wave_html_test.go, selfupdate/coverage_extra_test.go,
// cis/rules_test.go) restored the mutated value correctly afterwards — the
// defect is the UNSYNCHRONIZED WINDOW during which parallel siblings in the
// same package can observe the mutated value, not a state leak. It surfaced
// once, by accident, when a new test happened to read a relative path while
// wave_html_test.go's Chdir was in effect; nothing forced it to surface
// sooner, and nothing stopped it recurring.
//
// Why this lives in internal/collectors specifically: this package has 6
// tests that are both parallel AND read a relative path (see the fixture
// tests in disk_test.go, fdlimits_test.go, io_test.go, network_quick_test.go,
// processes_test.go) but zero mutation hazards today — meaning, unlike
// render/selfupdate/cis, it has NO grace period: the next global-mutating
// parallel test added here is immediately live, not latent. That made it the
// right place to anchor the guard. The scan itself is repo-wide (not scoped
// to this package) because the bug class is repo-wide — the cis instance in
// particular only exists because the PARENT mutates and the SUBTESTS are
// parallel, a shape a check scoped to "does this one function have both"
// would miss entirely; walking each top-level test's whole AST subtree in one
// pass (ast.Inspect naturally descends into nested t.Run closures) catches
// that shape without needing to special-case parent-vs-subtest at all.
func TestNoGlobalMutationInParallelTests(t *testing.T) {
	root := repoRootForGovernanceTest(t)

	testFiles := collectTestFiles(t, root)
	if len(testFiles) < 500 { // sanity: repo has ~693 _test.go files as of writing
		t.Fatalf("only found %d _test.go files under %s — the walk is broken or root is wrong, "+
			"this test would silently police nothing", len(testFiles), root)
	}

	fset := token.NewFileSet()
	varCache := map[string]map[string]bool{} // dir -> package-level var names

	var violations []string
	for _, path := range testFiles {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		dir := filepath.Dir(path)
		vars, ok := varCache[dir]
		if !ok {
			vars = packageLevelVarNames(t, fset, dir)
			varCache[dir] = vars
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			relPath = path
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !isTestFunc(fn) {
				continue
			}
			violations = append(violations, scanTestTree(fset, relPath, fn, vars)...)
		}
	}

	var real []string
	for _, v := range violations {
		site, _, found := strings.Cut(v, " | ")
		if found {
			if reason, exempted := parallelMutationExemptions[site]; exempted {
				t.Logf("exempted %s: %s", site, reason)
				continue
			}
		}
		real = append(real, v)
	}
	sort.Strings(real)

	if len(real) > 0 {
		t.Errorf("%d global mutation(s) found inside a t.Parallel() test tree:\n  %s\n\n"+
			"Each one races every OTHER parallel test in the same package that reads "+
			"process/package-global state (CWD, env vars, package vars) while this test's "+
			"mutation is in effect — restoring it afterwards does not fix this, the window "+
			"while parallel siblings can observe the mutated value is what's unsynchronized. "+
			"Fix by removing the need for the mutation (t.TempDir() + absolute paths instead "+
			"of os.Chdir; inject the value instead of swapping a package var) or by dropping "+
			"t.Parallel() from the test/subtree. If the mutation is genuinely safe, add a "+
			"parallelMutationExemptions entry in this file with a stated reason.",
			len(real), strings.Join(real, "\n  "))
	}
}

// parallelMutationExemptions lists "relative/path/to/file.go:LINE" sites
// explicitly allowed to mutate global state inside a t.Parallel() test tree,
// each with the reason it's safe. Empty today — every hazard found by the
// audit that motivated this test was fixed rather than exempted. Add an
// entry only when the mutation is provably safe (e.g. synchronized some other
// way) — a reason is required, this is not a suppression list.
var parallelMutationExemptions = map[string]string{}

// mutationPatterns maps "pkg.Func" call targets treated as global mutation.
var mutationPatterns = map[string]bool{
	"os.Chdir":      true,
	"os.Setenv":     true,
	"os.Unsetenv":   true,
	"flag.Set":      true,
	"log.SetOutput": true,
	"signal.Notify": true,
}

// scanTestTree walks fn's ENTIRE body (including nested t.Run closures —
// ast.Inspect descends into FuncLits automatically, no special-casing of
// t.Run needed) once, collecting whether t.Parallel() is called anywhere in
// the tree and every mutation site found anywhere in the tree. If both are
// non-empty, every mutation site is reported as a violation: it does not
// matter whether the Parallel() call and the mutation are in the same
// function, a parent, or a subtest — once ANY part of the tree is parallel,
// the whole tree runs in the concurrency-exposed phase.
func scanTestTree(fset *token.FileSet, relPath string, fn *ast.FuncDecl, pkgVars map[string]bool) []string {
	hasParallel := false
	type hit struct {
		line int
		desc string
	}
	var mutations []hit

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Parallel" {
				hasParallel = true
				return true
			}
			if pkgIdent, ok := sel.X.(*ast.Ident); ok {
				key := pkgIdent.Name + "." + sel.Sel.Name
				if mutationPatterns[key] {
					mutations = append(mutations, hit{fset.Position(node.Pos()).Line, key + "(...)"})
				}
			}
		case *ast.AssignStmt:
			if node.Tok != token.ASSIGN {
				return true
			}
			for _, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if ok && pkgVars[id.Name] {
					mutations = append(mutations, hit{fset.Position(node.Pos()).Line, "package var " + id.Name + " reassigned"})
				}
			}
		}
		return true
	})

	if !hasParallel || len(mutations) == 0 {
		return nil
	}
	out := make([]string, 0, len(mutations))
	for _, m := range mutations {
		site := fmt.Sprintf("%s:%d", relPath, m.line)
		out = append(out, fmt.Sprintf("%s | %s (in %s's t.Parallel() tree)", site, m.desc, fn.Name.Name))
	}
	return out
}

func isTestFunc(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Body == nil {
		return false
	}
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing" && sel.Sel.Name == "T"
}

// packageLevelVarNames returns every package-level `var` name declared in
// dir's .go files (production AND test files — a mutation of a var declared
// only in a _test.go helper is just as much a race as one declared in
// production code).
func packageLevelVarNames(t *testing.T, fset *token.FileSet, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir %s: %v", dir, err)
	}
	vars := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Join(dir, e.Name()), err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					if name.Name != "_" {
						vars[name.Name] = true
					}
				}
			}
		}
	}
	return vars
}

// collectTestFiles walks root for *_test.go files, skipping the same
// throwaway/generated directories the manual audit excluded: .scratch/ (repo
// scratch dir), .git/, and .claude/ (including .claude/worktrees/, which are
// full duplicate checkouts — walking them would double-count every hazard).
func collectTestFiles(t *testing.T, root string) []string {
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
		if strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for _test.go files: %v", root, err)
	}
	return files
}

// repoRootForGovernanceTest resolves the module root via this test file's own
// path (runtime.Caller), NOT the process working directory — a relative path
// here would reintroduce exactly the CWD-race class this whole test exists to
// police: this test itself calls t.Parallel() nowhere, but other parallel
// tests in this package do (see the fixture tests this file's doc comment
// names), and any one of them could still have a CWD mutated by an in-package
// hazard added later. Anchoring on an absolute, self-resolved path sidesteps
// the question entirely rather than relying on package discipline.
func repoRootForGovernanceTest(t *testing.T) string {
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
