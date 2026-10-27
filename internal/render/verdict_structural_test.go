package render

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// GUARD B (structural) — DD-VERDICT-1, DEFECT-CLASSES.md C1.
//
// verdict.go is the only file allowed to derive an overall verdict or to spell
// the all-clear wording. This test parses the production files that render or
// record a `dsd health` run and fails if any other file
//
//   - contains a string literal that is all-clear wording ("All checks passed",
//     "System healthy", "HEALTHY", "remained healthy", "currently healthy", ...), or
//   - declares a function that tests for the severities "CRIT"/"WARN" and also
//     produces the string "OK" or "HEALTHY" (store.VerdictFromInsights switched
//     on a []string of levels, summarizeInsights on Insight.Level) — a private
//     re-derivation of the verdict, which is how the terminal banner, both
//     reports, the history entry and the story came to say "healthy" for a run
//     whose collectors had errored.
//
// A new output needs no exemption: it calls Verdict and prints the string
// VerdictInfo gives it. If a literal here is genuinely not a run verdict (say a
// per-subsystem summary), add the file to verdictGuardExempt with a reason.
//
// Scope. Only the paths that render or record the multi-check `dsd health` run
// are policed (internal/render, internal/store, and the cmd files that read
// history/baselines back). The per-subcommand one-liners in cmd/ ("CPU healthy.
// Checks passed", "Disk healthy. ...") summarize a single collector with their
// own false-OK handling and are a separate surface (see COLLECTOR-SWEEP.md).

// verdictGuardRoots are repo-relative directories (all non-test .go files in
// them, not recursive) and files in scope.
var verdictGuardRoots = []string{
	"internal/render",
	"internal/store",
	"cmd/health.go",
	"cmd/history.go",
	"cmd/story.go",
	"cmd/share.go",
	"cmd/diff.go",
}

// verdictGuardAllowedFile is the single place verdict derivation and all-clear
// wording may live.
const verdictGuardAllowedFile = "internal/render/verdict.go"

// verdictGuardExempt: repo-relative file -> reason it may carry matching text
// although it is not deriving a run verdict. Empty on purpose; a reason is
// required, this is not a suppression list.
var verdictGuardExempt = map[string]string{}

// verdictGuardExemptFuncs: "repo-relative file:FuncName" -> reason the function
// maps a PER-CHECK status, not the run's overall verdict.
var verdictGuardExemptFuncs = map[string]string{
	"internal/render/html.go:buildHTMLCheckRows": "labels one row of the per-check table with that check's own status " +
		"(INFO — a collector that errored or an unmeasurable value — has its own explicit case); the page verdict is HTMLVerdict's",
}

var allClearRe = regexp.MustCompile(`(?i)checks? passed|system (is )?healthy|remained healthy|currently healthy|all checks (are )?(ok|healthy)|verdict: ok`)

type verdictFinding struct {
	file string // repo-relative
	line int
	kind string // "literal" | "func"
	what string
}

func (f verdictFinding) String() string {
	return f.file + ":" + strconv.Itoa(f.line) + " [" + f.kind + "] " + f.what
}

// scanForVerdictDerivation parses one Go file and returns every place it
// derives a verdict or spells all-clear wording.
func scanForVerdictDerivation(t *testing.T, path, rel string) []verdictFinding {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []verdictFinding

	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if allClearRe.MatchString(s) || s == "HEALTHY" {
			out = append(out, verdictFinding{rel, fset.Position(lit.Pos()).Line, "literal", strconv.Quote(s)})
		}
		return true
	})

	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if _, exempt := verdictGuardExemptFuncs[rel+":"+fd.Name.Name]; exempt {
			continue
		}
		if funcDerivesVerdict(fd) {
			out = append(out, verdictFinding{rel, fset.Position(fd.Pos()).Line, "func", fd.Name.Name + " tests CRIT/WARN and yields \"OK\"/\"HEALTHY\""})
		}
	}
	return out
}

func funcDerivesVerdict(fd *ast.FuncDecl) bool {
	var testsSeverity, yieldsOK bool
	isLit := func(e ast.Expr, vals ...string) bool {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return false
		}
		s, err := strconv.Unquote(bl.Value)
		if err != nil {
			return false
		}
		for _, v := range vals {
			if s == v {
				return true
			}
		}
		return false
	}
	anyLit := func(exprs []ast.Expr, vals ...string) bool {
		for _, e := range exprs {
			if isLit(e, vals...) {
				return true
			}
		}
		return false
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			if isLit(x, "CRIT", "WARN") {
				testsSeverity = true
			}
		case *ast.ReturnStmt:
			if anyLit(x.Results, "OK", "HEALTHY") {
				yieldsOK = true
			}
		case *ast.AssignStmt:
			if anyLit(x.Rhs, "OK", "HEALTHY") {
				yieldsOK = true
			}
		case *ast.ValueSpec:
			if anyLit(x.Values, "OK", "HEALTHY") {
				yieldsOK = true
			}
		}
		return true
	})
	return testsSeverity && yieldsOK
}

func verdictGuardFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, r := range verdictGuardRoots {
		full := filepath.Join(root, filepath.FromSlash(r))
		fi, err := os.Stat(full)
		if err != nil {
			t.Fatalf("verdictGuardRoots entry %q does not exist: %v — update the list when a file moves", r, err)
		}
		if !fi.IsDir() {
			files = append(files, full)
			continue
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files = append(files, filepath.Join(full, name))
		}
	}
	return files
}

func TestGuardB_NoSecondVerdictDerivation(t *testing.T) {
	root := repoRootForStatusSwitchGovernance(t)
	files := verdictGuardFiles(t, root)
	if len(files) < 30 { // sanity: render alone has ~50 production files
		t.Fatalf("only %d files in scope — the walk is broken, this guard would police nothing", len(files))
	}

	var violations []string
	sawAllowed := false
	for _, path := range files {
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == verdictGuardAllowedFile {
			sawAllowed = true
			continue
		}
		if reason, ok := verdictGuardExempt[rel]; ok {
			t.Logf("exempt %s: %s", rel, reason)
			continue
		}
		for _, f := range scanForVerdictDerivation(t, path, rel) {
			violations = append(violations, f.String())
		}
	}
	if !sawAllowed {
		t.Fatalf("%s not found in scope — the guard's single allowed file moved; update verdictGuardAllowedFile", verdictGuardAllowedFile)
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("%d place(s) derive an overall verdict or spell all-clear wording outside %s:\n  %s\n\n"+
			"Call render.Verdict(results, insights) and print what VerdictInfo gives you (TerminalBanner, MarkdownSummary, "+
			"HTMLVerdict, ShareLine, Story*...). Adding a second derivation is how the terminal, the reports and the history "+
			"came to say \"healthy\" for a run whose checks could not run (DEFECT-CLASSES.md C1).",
			len(violations), verdictGuardAllowedFile, strings.Join(violations, "\n  "))
	}
}

// The scanner must actually fire: run it over the negative example in testdata
// (never compiled) and require every site it marks with GUARD-B-EXPECT.
func TestGuardB_NegativeExampleFires(t *testing.T) {
	path := filepath.Join("testdata", "verdictguard_bad", "derives_verdict.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wantKinds := map[int]string{} // line of the declaration after the marker -> kind
	lines := strings.Split(string(src), "\n")
	for i, l := range lines {
		if _, kind, ok := strings.Cut(l, "GUARD-B-EXPECT: "); ok {
			wantKinds[i+2] = strings.TrimSpace(kind) // marker line i+1 (1-based); declaration is the next line
		}
	}
	if len(wantKinds) != 4 {
		t.Fatalf("negative example should mark 4 sites, found %d", len(wantKinds))
	}
	got := scanForVerdictDerivation(t, path, "testdata/verdictguard_bad/derives_verdict.go")
	for line, kind := range wantKinds {
		hit := false
		for _, f := range got {
			if f.kind == kind && f.line == line {
				hit = true
			}
		}
		if !hit {
			t.Errorf("guard missed the %s derivation at testdata line %d; findings: %v", kind, line, got)
		}
	}
}
