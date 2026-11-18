package readonly

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// norm renders a toolRule field as a sorted, order-insensitive set: a list of lists becomes one
// joined string per inner list, a flat list one string per element.
func norm(fset *token.FileSet, e ast.Expr) string {
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		var b bytes.Buffer
		_ = printer.Fprint(&b, fset, e)
		return b.String()
	}
	var items []string
	for _, el := range cl.Elts {
		if inner, ok := el.(*ast.CompositeLit); ok {
			var parts []string
			for _, x := range inner.Elts {
				var b bytes.Buffer
				_ = printer.Fprint(&b, fset, x)
				parts = append(parts, b.String())
			}
			items = append(items, "["+strings.Join(parts, " ")+"]")
		} else {
			var b bytes.Buffer
			_ = printer.Fprint(&b, fset, el)
			items = append(items, b.String())
		}
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

// contractEntries parses file and returns, for the package-level `var name = map[...]...{...}`,
// each key -> its fields normalised by norm. It compares SOURCE, not values, because cmd's
// contract lives in package cmd_test and cannot be imported here.
func contractEntries(t *testing.T, file, name string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			if len(vs.Names) != 1 || vs.Names[0].Name != name || len(vs.Values) != 1 {
				continue
			}
			cl, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatalf("%s in %s is not a composite literal", name, file)
			}
			for _, el := range cl.Elts {
				kv := el.(*ast.KeyValueExpr)
				var key bytes.Buffer
				_ = printer.Fprint(&key, fset, kv.Key)
				var fields []string
				if rule, ok := kv.Value.(*ast.CompositeLit); ok {
					for _, fe := range rule.Elts {
						fkv := fe.(*ast.KeyValueExpr)
						var fn bytes.Buffer
						_ = printer.Fprint(&fn, fset, fkv.Key)
						fields = append(fields, fn.String()+"="+norm(fset, fkv.Value))
					}
				}
				sort.Strings(fields)
				out[strings.Trim(key.String(), `"`)] = strings.Join(fields, ";")
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no entries found for %s in %s: parity check would be vacuous", name, file)
	}
	return out
}

// TestExecAllowlistContract_ParityWithCmd fails when this package's port of the exec allowlist
// contract drifts from cmd/execallowlist_contract_test.go (the hand-reviewed original). It checks
// the entries as written in source; it does NOT check that either contract matches what the
// collectors actually run (that is what FuzzReadOnlyClaim / FuzzCommandAllowlist are for).
// Drift here is how vmware-toolbox-cmd went missing from the port and made FuzzReadOnlyClaim
// fail on every VMware guest while staying green on CI.
func TestExecAllowlistContract_ParityWithCmd(t *testing.T) {
	orig := contractEntries(t, "../../cmd/execallowlist_contract_test.go", "execAllowlistContract")
	port := contractEntries(t, "allowlist_test.go", "execAllowlistContract")
	for k, v := range orig {
		pv, ok := port[k]
		if !ok {
			t.Errorf("binary %q is in cmd's contract but missing from the readonly port", k)
		} else if pv != v {
			t.Errorf("binary %q differs between cmd contract and readonly port:\n cmd:      %s\n readonly: %s", k, v, pv)
		}
	}
	for k := range port {
		if _, ok := orig[k]; !ok {
			t.Errorf("binary %q is in the readonly port but not in cmd's contract", k)
		}
	}
}
