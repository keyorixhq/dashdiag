package srcpath

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// guardSelf is exempt: it contains runtime.Caller in its calibration table.
const guardSelf = "internal/testutil/srcpath/runtime_caller_guard_test.go"

// TestNoTestOpensFilesViaRuntimeCallerPath is the static guard for the
// -trimpath contract (see the package comment): under -trimpath
// runtime.Caller's file name is an import path, so a test that feeds it to
// filepath.Dir/os.ReadFile/... passes on a plain build and breaks with
// -trimpath. Use srcpath.RepoRoot()/PkgDir() instead.
//
// It parses every *_test.go in the root module plus the non-test helpers under
// internal/testutil (loaded into test binaries) and reports any
// runtime.Caller(...) call whose second result (the file name) is bound to a
// name other than `_`. Callers that only want the pc or line stay legal.
//
// It does NOT check file names taken from runtime.CallersFrames (Frame.File),
// debug.Stack parsing, or a package shadowing the identifier `runtime`; none
// occur in the repo today. Hidden directories, testdata, vendor and nested
// modules are skipped.
func TestNoTestOpensFilesViaRuntimeCallerPath(t *testing.T) {
	root := RepoRoot()
	var violations []string
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return guardDirAction(root, path, d.Name())
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		inScope := strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "internal/testutil/")
		if !inScope || rel == guardSelf {
			return nil
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Errorf("parse %s: %v", rel, parseErr)
			return nil
		}
		scanned++
		for _, line := range runtimeCallerFileUses(fset, file) {
			violations = append(violations, rel+":"+line)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d test/testutil files — the walk is broken, this guard would police nothing", scanned)
	}
	t.Logf("scanned %d files", scanned)
	for _, v := range violations {
		t.Errorf("%s: runtime.Caller file name is not a filesystem path under -trimpath; "+
			"use srcpath.RepoRoot()/srcpath.PkgDir() (internal/testutil/srcpath)", v)
	}
}

func guardDirAction(root, path, name string) error {
	if path == root {
		return nil
	}
	if strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" || name == "node_modules" {
		return filepath.SkipDir
	}
	// Nested modules are scanned by their own `go test`.
	if modulePath(filepath.Join(path, "go.mod")) != "" {
		return filepath.SkipDir
	}
	return nil
}

// TestRuntimeCallerGuardCatchesAndSpares is the red/green calibration of the
// matcher: it must flag the file-name shapes and spare pc/line-only use.
func TestRuntimeCallerGuardCatchesAndSpares(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want int
	}{
		{"file via define", `_, thisFile, _, ok := runtime.Caller(0); _, _ = thisFile, ok`, 1},
		{"file via assign", `var f string; _, f, _, _ = runtime.Caller(0); _ = f`, 1},
		{"file via var", `var _, f, _, _ = runtime.Caller(0); _ = f`, 1},
		{"pc and line only", `pc, _, line, _ := runtime.Caller(1); _, _ = pc, line`, 0},
		{"all blank", `_, _, _, _ = runtime.Caller(0)`, 0},
		{"single-value call", `_ = runtime.NumCPU()`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", "package x\nimport \"runtime\"\nfunc f() { "+c.body+" }\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(runtimeCallerFileUses(fset, f)); got != c.want {
				t.Fatalf("got %d violations, want %d", got, c.want)
			}
		})
	}
}

func isRuntimeCaller(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Caller" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "runtime"
}

// runtimeCallerFileUses returns line numbers of each runtime.Caller call whose
// second result is bound to a non-blank name.
func runtimeCallerFileUses(fset *token.FileSet, f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 && isRuntimeCaller(x.Rhs[0]) && len(x.Lhs) >= 2 {
				if id, ok := x.Lhs[1].(*ast.Ident); !ok || id.Name != "_" {
					out = append(out, strconv.Itoa(fset.Position(x.Pos()).Line))
				}
			}
		case *ast.ValueSpec:
			if len(x.Values) == 1 && isRuntimeCaller(x.Values[0]) && len(x.Names) >= 2 && x.Names[1].Name != "_" {
				out = append(out, strconv.Itoa(fset.Position(x.Pos()).Line))
			}
		}
		return true
	})
	return out
}
