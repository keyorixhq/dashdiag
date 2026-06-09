package models

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestAvailableStructsImplementIsAvailable guards the runner.IsAvailable
// contract: every struct in this package with an `Available bool` field must
// have an IsAvailable() method (in availability.go). runner.IsAvailable no
// longer falls back to reflection, so a type that grows an Available field
// without the method would silently default to "present" — reintroducing the
// phantom "X ✅ OK" rows in dsd health --report that #129–#131 removed.
func TestAvailableStructsImplementIsAvailable(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing package source: %v", err)
	}

	withAvailableField := map[string]bool{}
	withMethod := map[string]bool{}

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						ts, ok := spec.(*ast.TypeSpec)
						if !ok {
							continue
						}
						st, ok := ts.Type.(*ast.StructType)
						if !ok {
							continue
						}
						if structHasAvailableBool(st) {
							withAvailableField[ts.Name.Name] = true
						}
					}
				case *ast.FuncDecl:
					if d.Recv != nil && d.Name.Name == "IsAvailable" {
						withMethod[receiverTypeName(d.Recv.List[0].Type)] = true
					}
				}
			}
		}
	}

	if len(withAvailableField) == 0 {
		t.Fatal("found no structs with an Available field — parser likely misconfigured")
	}

	for name := range withAvailableField {
		if !withMethod[name] {
			t.Errorf("type %s has an `Available bool` field but no IsAvailable() method — "+
				"add `func (i %s) IsAvailable() bool { return i.Available }` to availability.go "+
				"so dsd health --report hides it the same way live health does", name, name)
		}
	}
}

func structHasAvailableBool(st *ast.StructType) bool {
	for _, fld := range st.Fields.List {
		id, ok := fld.Type.(*ast.Ident)
		if !ok || id.Name != "bool" {
			continue
		}
		for _, n := range fld.Names {
			if n.Name == "Available" {
				return true
			}
		}
	}
	return false
}

// receiverTypeName returns the bare type name from a method receiver, handling
// both value (T) and pointer (*T) receivers.
func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
