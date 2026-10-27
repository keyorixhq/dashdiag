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

// TestNoRawGlobInProduction is the guard for the glob-swallows-EACCES class.
//
// filepath.Glob returns an empty, nil-error result for a directory it may not
// read, so any caller that treats len(matches)==0 as "nothing there" reads an
// unreadable directory as clean. The fix is source.GlobChecked (it asks the
// directory itself). This test fails on any production call to filepath.Glob or
// to the collectors' raw glob() helper outside internal/source, unless the
// enclosing function is in globExemptions with a reason.
//
// An exemption is only legitimate when the pattern's parent directory cannot
// be permission-denied to the caller (procfs/sysfs listings are world-readable;
// hidepid hides per-PID entries, it does not make /proc unlistable) or the
// result is purely enumerative with a documented fallback. A stale exemption
// (no matching call left) also fails, so the list can only shrink honestly.
func TestNoRawGlobInProduction(t *testing.T) {
	root := filepath.Join("..", "..")
	found := map[string]bool{} // "relpath:Func" -> seen
	var violations []string

	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if d.Name() == "testdata" || rel == "internal/source" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(path) // #nosec G304 -- walking our own repo tree
			if rerr != nil {
				return rerr
			}
			for _, fn := range rawGlobCallers(t, path, src) {
				key := rel + ":" + fn
				found[key] = true
				if _, ok := globExemptions[key]; !ok {
					violations = append(violations, key)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	sort.Strings(violations)
	for _, v := range violations {
		t.Errorf("raw glob in production code at %s: use source.GlobChecked (or collectors' globChecked) and surface the unreadable-dir flag; add a globExemptions row only if the parent dir cannot be permission-denied", v)
	}
	var stale []string
	for k := range globExemptions {
		if !found[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	for _, k := range stale {
		t.Errorf("stale globExemptions row %s: no raw glob call there any more; delete the row", k)
	}
}

// TestNoRawGlobGuard_FlagsNegativeExample proves the guard's detector is live:
// the testdata file contains both banned forms and one allowed form.
func TestNoRawGlobGuard_FlagsNegativeExample(t *testing.T) {
	path := filepath.Join("testdata", "globguard", "bad_glob.go.txt")
	src, err := os.ReadFile(path) // #nosec G304 -- fixed testdata path
	if err != nil {
		t.Fatal(err)
	}
	got := rawGlobCallers(t, path, src)
	sort.Strings(got)
	want := []string{"direct", "helper"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rawGlobCallers = %v, want %v (globChecked must not be flagged)", got, want)
	}
}

// rawGlobCallers returns the names of top-level functions in src that call
// filepath.Glob or the bare glob() helper.
func rawGlobCallers(t *testing.T, name string, src []byte) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	filepathName := ""
	for _, imp := range f.Imports {
		if imp.Path.Value == `"path/filepath"` {
			filepathName = "filepath"
			if imp.Name != nil {
				filepathName = imp.Name.Name
			}
		}
	}
	var out []string
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		hit := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				hit = hit || fn.Name == "glob"
			case *ast.SelectorExpr:
				if id, ok := fn.X.(*ast.Ident); ok && filepathName != "" && id.Name == filepathName && fn.Sel.Name == "Glob" {
					hit = true
				}
			}
			return true
		})
		if hit {
			out = append(out, funcKey(fd))
		}
	}
	return out
}

func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}
