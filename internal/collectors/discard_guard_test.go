package collectors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestNoErrorDiscardInProduction is the guard for the "failed read vanishes into a
// zero value" class (DEFECT-CLASSES.md C2/C3). It fails on any assignment in
// internal/collectors production code that throws away the error of a call into the
// source/exec/read helpers: `x, _ := readFile(p)`, `_ = cachedJSON(...)`,
// `_, _ = curSource().Cached(...)`.
//
// The set of helpers is DERIVED, not hand-listed:
//   - every method of the internal/source.Source interface (ReadFile, Glob, ReadDir,
//     Readlink, Stat, Statfs, Cached, Run), and
//   - every function in this package that calls curSource() and returns an error
//     last (readFile, openFile, runCmd*, cachedJSON, glob, globChecked, ...).
//
// A discard is allowed only when its enclosing function is in discardExemptions
// with a reason (discard_exemptions_test.go): the failure is carried another way,
// or an absent/failed answer is genuinely equivalent to the zero value for that
// code. A stale exemption (no matching discard left) also fails, so the list can
// only shrink honestly. New code should handle the error and set a sentinel.
func TestNoErrorDiscardInProduction(t *testing.T) {
	helpers := derivedHelperNames(t)
	found := map[string]bool{}
	var violations []string

	for _, path := range productionGoFiles(t) {
		rel := repoRel(path)
		for fn, calls := range discardsIn(t, path, helpers) {
			key := rel + ":" + fn
			found[key] = true
			if _, ok := discardExemptions[key]; !ok {
				violations = append(violations, key+"  ("+strings.Join(calls, ", ")+")")
			}
		}
	}

	var stale []string
	for key := range discardExemptions {
		if !found[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(violations)
	sort.Strings(stale)
	if len(violations) > 0 {
		t.Errorf("%d function(s) discard the error of a source/exec/read helper:\n  %s\n\n"+
			"Handle the error and set a sentinel (see COLLECTOR-SWEEP.md), or - only if a failed answer is "+
			"genuinely equivalent to the zero value - add a discardExemptions row with the reason.",
			len(violations), strings.Join(violations, "\n  "))
	}
	for _, key := range stale {
		t.Errorf("stale discardExemptions row %s: no discard there any more; delete the row", key)
	}
	for key, reason := range discardExemptions {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("discardExemptions row %s has no reason", key)
		}
	}
}

// The guard must actually catch a discard: run it over a negative example.
func TestDiscardGuardFlagsNegativeExample(t *testing.T) {
	helpers := derivedHelperNames(t)
	got := discardsIn(t, filepath.Join("testdata", "discardguard", "bad.go.txt"), helpers)
	for _, fn := range []string{"blankData", "blankOnly", "blankInIf", "blankViaSource"} {
		if _, ok := got[fn]; !ok {
			t.Errorf("negative example %s was not flagged", fn)
		}
	}
	for _, fn := range []string{"handled", "namedErr", "unrelatedCall"} {
		if _, ok := got[fn]; ok {
			t.Errorf("clean example %s was wrongly flagged", fn)
		}
	}
}

// derivedHelperNames returns the helper set described on the guard test.
func derivedHelperNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}

	// 1. Source interface methods, from internal/source.
	fset := token.NewFileSet()
	srcDir := filepath.Join("..", "source")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("reading internal/source: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(srcDir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				ts, ok := sp.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "Source" {
					continue
				}
				it, ok := ts.Type.(*ast.InterfaceType)
				if !ok {
					continue
				}
				for _, m := range it.Methods.List {
					for _, n := range m.Names {
						names[n.Name] = true
					}
				}
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("derived no Source methods: has internal/source/source.go's Source interface moved?")
	}

	// 2. Package functions that call curSource() and return an error last.
	for _, path := range productionGoFiles(t) {
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil || !returnsErrorLast(fd) {
				continue
			}
			callsSource := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "curSource" {
						callsSource = true
					}
				}
				return !callsSource
			})
			if callsSource {
				names[fd.Name.Name] = true
			}
		}
	}
	return names
}

func returnsErrorLast(fd *ast.FuncDecl) bool {
	res := fd.Type.Results
	if res == nil || len(res.List) == 0 {
		return false
	}
	id, ok := res.List[len(res.List)-1].Type.(*ast.Ident)
	return ok && id.Name == "error"
}

// discardsIn returns, per enclosing function, the helper names whose error result
// is assigned to the blank identifier.
func discardsIn(t *testing.T, path string, helpers map[string]bool) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string][]string{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			name = recvTypeName(fd.Recv.List[0].Type) + "." + name
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := calleeName(call)
			if !helpers[callee] {
				return true
			}
			// The error is the last result of every derived helper.
			if id, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident); ok && id.Name == "_" {
				out[name] = append(out[name], callee)
			}
			return true
		})
	}
	return out
}

func calleeName(c *ast.CallExpr) string {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

func recvTypeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr:
		return recvTypeName(v.X)
	}
	return "?"
}

// productionGoFiles lists internal/collectors non-test .go files.
func productionGoFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." {
				return filepath.SkipDir // testdata and any subpackage
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/collectors: %v", err)
	}
	sort.Strings(files)
	return files
}

func repoRel(path string) string {
	return "internal/collectors/" + filepath.ToSlash(path)
}

// A discard exempted as "already vetted in globExemptions" must really be vetted
// there: the two lists may not drift apart.
func TestDiscardGlobRowsAreVettedInGlobExemptions(t *testing.T) {
	for key, reason := range discardExemptions {
		if reason != rsGlobVetted {
			continue
		}
		if _, ok := globExemptions[key]; !ok {
			t.Errorf("%s is exempted as vetted in globExemptions but has no row there", key)
		}
	}
}

// Every exemption reason must say something: a blank or one-word reason is not a
// justification.
func TestDiscardExemptionReasonsAreSubstantive(t *testing.T) {
	for key, reason := range discardExemptions {
		if len(strings.Fields(reason)) < 5 {
			t.Errorf("%s: reason %q is too short to justify a discard", key, reason)
		}
	}
}
