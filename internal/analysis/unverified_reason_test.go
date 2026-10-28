package analysis

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestApplyThresholds_ErrorReason: a collector error becomes an Unverified insight
// whose reason is derived from the error with errors.Is, never from its text.
func TestApplyThresholds_ErrorReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"deadline", fmt.Errorf("collector X timed out: %w", context.DeadlineExceeded), models.ReasonTimeout},
		{"permission", &fs.PathError{Op: "open", Path: "/x", Err: fs.ErrPermission}, models.ReasonUnreadable},
		{"not recorded", fmt.Errorf("%w: ReadFile /sys/x", source.ErrNotRecorded), models.ReasonNotRecorded},
		{"parse", fmt.Errorf("zpool: %w", models.ErrParse), models.ReasonParse},
		{"other", errors.New("boom"), models.ReasonCollectorError},
		// Text that merely sounds like a cause must not be classified by its words.
		{"text only", errors.New("timed out: permission denied"), models.ReasonCollectorError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ins := ApplyThresholds([]runner.Result{{Name: "Net", Err: c.err}}, Thresholds{}, platform.CloudEnvironment(0), platform.ContainerContext{})
			if len(ins) != 1 || !ins[0].Unverified {
				t.Fatalf("want one Unverified insight, got %+v", ins)
			}
			if ins[0].UnverifiedReason != c.want {
				t.Errorf("UnverifiedReason = %q, want %q", ins[0].UnverifiedReason, c.want)
			}
		})
	}
}

// TestApplyThresholds_ReplayGapRelabels: a replayed collector that hit a recording
// gap reports its read failures as not_recorded, but needs_root and timeout keep
// their own cause.
func TestApplyThresholds_ReplayGapRelabels(t *testing.T) {
	t.Parallel()
	ins := []models.Insight{
		unverifiedInsight(models.ReasonUnreadable, "INFO", "A", "m", nil),
		unverifiedInsight(models.ReasonCollectorError, "INFO", "B", "m", nil),
		unverifiedInsight(models.ReasonParse, "INFO", "C", "m", nil),
		unverifiedInsight(models.ReasonTimeout, "INFO", "D", "m", nil),
		{Level: "WARN", Check: "E", Message: "m"},
	}
	ins[0].NeedsRoot = true
	ins[0].UnverifiedReason = models.ReasonNeedsRoot
	markNotRecorded(ins)
	want := []string{models.ReasonNeedsRoot, models.ReasonNotRecorded, models.ReasonNotRecorded, models.ReasonTimeout, ""}
	for i, w := range want {
		if ins[i].UnverifiedReason != w {
			t.Errorf("insight %s: reason %q, want %q", ins[i].Check, ins[i].UnverifiedReason, w)
		}
	}
}

// TestNeedsRootInsightReason pins the existing needs_root refinement into the new field.
func TestNeedsRootInsightReason(t *testing.T) {
	prev := isRoot
	defer func() { isRoot = prev }()
	isRoot = func() bool { return false }
	if got := needsRootInsight("INFO", "X", "m", nil); got.UnverifiedReason != models.ReasonNeedsRoot || !got.NeedsRoot {
		t.Errorf("non-root: %+v", got)
	}
	isRoot = func() bool { return true }
	if got := needsRootInsight("INFO", "X", "m", nil); got.UnverifiedReason != models.ReasonUnreadable || got.NeedsRoot {
		t.Errorf("root: %+v", got)
	}
}

// unverifiedSetExemptions are the non-Insight types that happen to have an
// "Unverified" field, so setting it is not creating an Insight. Keyed by file.
var unverifiedSetExemptions = map[string]string{
	"internal/cis/types.go":                    "models.CISResult.Unverified, not an Insight",
	"internal/baseline/baseline.go":            "copies Insight.Unverified into a snapshot CheckResult",
	"internal/collectors/maintenance_linux.go": "data field MaintenanceInfo.Unverified, read by analysis",
	"internal/collectors/drbd_linux.go":        "data field DRBDInfo.Unverified, read by analysis",
}

// TestUnverifiedInsightAlwaysHasReason is the guard for UnverifiedReason: an
// Insight can only become Unverified through unverifiedInsight (which requires a
// reason), and every call passes a models.Reason* constant that is a valid
// UnverifiedReasons value, or a variable the test lists below. A new Unverified
// insight without a reason fails here.
func TestUnverifiedInsightAlwaysHasReason(t *testing.T) {
	valid := map[string]bool{}
	for _, r := range models.UnverifiedReasons {
		valid[r] = true
	}
	constName := map[string]string{
		"ReasonNeedsRoot": models.ReasonNeedsRoot, "ReasonTimeout": models.ReasonTimeout,
		"ReasonUnreadable": models.ReasonUnreadable, "ReasonCollectorError": models.ReasonCollectorError,
		"ReasonParse": models.ReasonParse, "ReasonNotRecorded": models.ReasonNotRecorded,
	}
	// Calls whose first argument is computed, with why that is right.
	dynamic := map[string]string{
		"heuristics.go:ApplyThresholds": "models.ReasonOfErr(r.Err) of the collector's own error (errors.Is)",
	}

	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := ce.Fun.(*ast.Ident); !ok || id.Name != "unverifiedInsight" {
					return true
				}
				calls++
				pos := fset.Position(ce.Pos())
				if len(ce.Args) != 5 {
					t.Errorf("%s: unverifiedInsight needs (reason, level, check, message, hints)", pos)
					return true
				}
				if sel, ok := ce.Args[0].(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "models" {
						if v, known := constName[sel.Sel.Name]; known && valid[v] {
							return true
						}
					}
					t.Errorf("%s: %s is not an UnverifiedReasons value", pos, sel.Sel.Name)
					return true
				}
				if _, ok := dynamic[f+":"+fd.Name.Name]; ok {
					return true
				}
				t.Errorf("%s: reason must be a models.Reason* constant (or an entry in dynamic with a why)", pos)
				return true
			})
		}
	}
	if calls < 100 {
		t.Fatalf("scanned only %d unverifiedInsight calls; the guard lost its target", calls)
	}

	// Nothing else may mark an Insight Unverified.
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, de fs.DirEntry, err error) error {
			if err != nil || de.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			af, perr := parser.ParseFile(token.NewFileSet(), p, nil, 0)
			if perr != nil {
				return nil
			}
			ast.Inspect(af, func(n ast.Node) bool {
				var hit bool
				switch x := n.(type) {
				case *ast.KeyValueExpr:
					if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Unverified" && isTrue(x.Value) {
						hit = true
					}
				case *ast.AssignStmt:
					for i, l := range x.Lhs {
						if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "Unverified" && i < len(x.Rhs) && isTrue(x.Rhs[i]) {
							hit = true
						}
					}
				}
				if hit && rel != "internal/analysis/heuristics.go" {
					if _, ok := unverifiedSetExemptions[rel]; !ok {
						t.Errorf("%s sets Unverified outside unverifiedInsight: add a reason via unverifiedInsight or an exemption with why", rel)
					}
				}
				return true
			})
			return nil
		})
	}
}

// isTrue reports whether e is the literal true: copying someone else's
// Unverified value into a view struct does not create an Unverified insight.
func isTrue(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "true"
}
