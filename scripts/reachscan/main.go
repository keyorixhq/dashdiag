// Command reachscan lists the functions in this module that parse untrusted
// text (command output, /proc and /sys files, captured bundles, YAML/JSON)
// and ranks them by production call-site count and by whether a Fuzz target
// already reaches them. It also lists every library function (third-party,
// plus the standard-library decoders) that production code calls on string,
// []byte or io.Reader data.
//
// It is a reachability-first planning tool for fuzzing, not a proof. It runs
// offline: packages are type-checked with go/types and the "source" importer,
// so no golang.org/x/tools dependency and no network.
//
// Usage (from the module root):
//
//	go run ./scripts/reachscan -goos linux -top 40 > .scratch/reach.md
//
// What it does NOT verify:
//   - Taint. A function counts as a parser when it takes string, []byte,
//     []string, io.Reader, *bufio.Scanner or *bufio.Reader and its name or body
//     looks like parsing. Whether the argument really comes from an external
//     source is not traced; a parser fed only constants still ranks.
//   - Dynamic calls precisely. Interface method calls are not followed.
//     Func values are approximated: naming a module function reaches it, and
//     reading a package-level variable reaches every function that assigns
//     it (so a registry such as CISRules = buildRules() makes its Check
//     closures reachable from ruleByID). That over-approximates for shared
//     variables and still misses values passed through parameters, so
//     "transitive" is neither a strict lower nor upper bound.
//   - Fuzz coverage is name-based: a candidate is "direct" when its name is
//     called from a file that declares a Fuzz target in the same package (or
//     through pkg.Name from any fuzz file). Name collisions can overstate it.
//   - One GOOS per run. Files excluded by build tags for that GOOS are not
//     scanned; run once per platform for the full picture.
package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const modulePath = "github.com/keyorixhq/dashdiag"

// parseNameRe marks a function name as parser-shaped.
var parseNameRe = regexp.MustCompile(`(?i)(parse|decode|unmarshal|load|scan|extract|apply|split|lines|tokeni[sz]e|classify|interpret)`)

// primitives are the calls that make a body look like it is parsing text.
var primitives = map[string]bool{
	"strings.Fields": true, "strings.Split": true, "strings.SplitN": true, "strings.Cut": true,
	"strings.TrimSpace": true, "strings.HasPrefix": true, "strings.TrimPrefix": true, "strings.Index": true,
	"strings.Lines": true, "strings.SplitSeq": true, "strings.FieldsSeq": true, "strings.FieldsFunc": true,
	"bytes.Fields": true, "bytes.Split": true, "bytes.Cut": true, "bytes.TrimSpace": true,
	"strconv.Atoi": true, "strconv.ParseInt": true, "strconv.ParseUint": true, "strconv.ParseFloat": true,
	"strconv.ParseBool": true, "strconv.Unquote": true, "fmt.Sscanf": true, "fmt.Sscan": true,
	"bufio.NewScanner": true, "bufio.NewReader": true,
	"encoding/json.Unmarshal": true, "encoding/json.NewDecoder": true, "encoding/xml.Unmarshal": true,
	"encoding/csv.NewReader": true, "gopkg.in/yaml.v3.Unmarshal": true, "gopkg.in/yaml.v3.NewDecoder": true,
	"time.Parse": true, "time.ParseDuration": true,
}

// decoderPkgs are standard-library packages whose calls on untrusted bytes
// are listed alongside third-party ones.
var decoderPkgs = map[string]bool{
	"encoding/json": true, "encoding/xml": true, "encoding/csv": true, "encoding/base64": true,
	"encoding/hex": true, "encoding/gob": true, "archive/tar": true, "archive/zip": true,
	"compress/gzip": true, "regexp": true, "strconv": true, "time": true, "text/template": true,
	"net/url": true, "net/netip": true, "net": true, "mime": true,
}

type candidate struct {
	Key       string // pkgpath.[Recv.]Name
	Pkg       string
	Name      string
	Pos       string
	Params    string
	Score     int // parsing primitives in the body
	Calls     int // production call sites
	Direct    bool
	Transitiv bool
}

type extCall struct {
	Key   string
	Path  string // package path of the callee
	Calls int
	Pkgs  map[string]bool
}

// scanner holds what one run collects across all packages.
type scanner struct {
	root  string
	fset  *token.FileSet
	imp   types.Importer
	cands map[string]*candidate
	calls map[string]int             // qualified callee -> production call sites
	graph map[string]map[string]bool // caller key -> callee keys (module only)
	ext   map[string]*extCall
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "reachscan:", err)
		os.Exit(2)
	}
}

// run parses args, scans the module and writes the report to w.
func run(args []string, w io.Writer) error {
	fl := flag.NewFlagSet("reachscan", flag.ContinueOnError)
	root := fl.String("root", ".", "module root")
	goos := fl.String("goos", "linux", "GOOS to evaluate build tags for")
	top := fl.Int("top", 40, "rows in the uncovered ranking")
	listAll := fl.Bool("all", os.Getenv("REACHSCAN_ALL") != "", "also list every candidate (default from REACHSCAN_ALL)")
	if err := fl.Parse(args); err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}

	// The source importer reads build.Default, so the GOOS must be set there.
	build.Default.GOOS = *goos
	build.Default.CgoEnabled = false
	if err := ensureGOROOT(); err != nil {
		return err
	}

	fset := token.NewFileSet()
	s := &scanner{
		root: *root, fset: fset, imp: importer.ForCompiler(fset, "source", nil),
		cands: map[string]*candidate{}, calls: map[string]int{},
		graph: map[string]map[string]bool{}, ext: map[string]*extCall{},
	}
	// Type errors are ignored per package, so an importer that cannot see
	// the standard library would silently drop every primitive and library
	// call. Fail instead of printing a plausible but empty report.
	if _, err := s.imp.Import("strings"); err != nil {
		return fmt.Errorf("source importer cannot load the standard library (GOROOT=%q): %w", build.Default.GOROOT, err)
	}
	dirs := packageDirs(*root)
	for _, dir := range dirs {
		s.scanPackage(dir)
	}
	all := s.rank(fuzzRoots(*root, dirs))
	printCandidates(w, all, *goos, *top)
	printLibraryCalls(w, s.ext)
	if *listAll {
		printAll(w, all)
	}
	return nil
}

// ensureGOROOT fills build.Default.GOROOT when the binary was built with
// -trimpath, which leaves it empty and hides the standard library sources
// from the source importer.
func ensureGOROOT() error {
	if build.Default.GOROOT != "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "env", "GOROOT").Output()
	if err != nil {
		return fmt.Errorf("resolving GOROOT with go env (binary built with -trimpath): %w", err)
	}
	build.Default.GOROOT = strings.TrimSpace(string(out))
	return nil
}

// packageDirs lists every directory under root that may hold a package,
// skipping hidden dirs, testdata, vendor and the tooling trees.
func packageDirs(root string) []string {
	var dirs []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped, not fatal
		}
		if !d.IsDir() {
			return nil
		}
		n := d.Name()
		if p != root && (strings.HasPrefix(n, ".") || n == "testdata" || n == "vendor" || n == "node_modules" ||
			n == "scripts" || n == "testutil") {
			return filepath.SkipDir
		}
		dirs = append(dirs, p)
		return nil
	})
	return dirs
}

func (s *scanner) scanPackage(dir string) {
	bp, err := build.Default.ImportDir(dir, 0)
	if err != nil || len(bp.GoFiles) == 0 {
		return
	}
	rel, _ := filepath.Rel(s.root, dir)
	pkgPath := modulePath
	if rel != "." {
		pkgPath += "/" + filepath.ToSlash(rel)
	}
	var files []*ast.File
	for _, f := range bp.GoFiles {
		if af, err := parser.ParseFile(s.fset, filepath.Join(dir, f), nil, parser.SkipObjectResolution); err == nil {
			files = append(files, af)
		}
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
	conf := types.Config{Importer: s.imp, Error: func(error) {}}
	_, _ = conf.Check(pkgPath, s.fset, files, info)

	for _, af := range files {
		for _, decl := range af.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
				s.scanFunc(fd, info, pkgPath)
			}
		}
	}
}

func (s *scanner) addEdge(from, to string) {
	if s.graph[from] == nil {
		s.graph[from] = map[string]bool{}
	}
	s.graph[from][to] = true
}

func (s *scanner) scanFunc(fd *ast.FuncDecl, info *types.Info, pkgPath string) {
	obj, _ := info.Defs[fd.Name].(*types.Func)
	if obj == nil {
		return
	}
	key := funcKey(obj)
	s.registryEdges(fd, info, key)
	score := 0
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callee := calleeFunc(info, ce); callee != nil && s.recordCall(info, ce, callee, key, pkgPath) {
			score++
		}
		return true
	})
	params, textual := textParams(obj)
	if !textual || !parseNameRe.MatchString(fd.Name.Name) && score < 3 {
		return
	}
	pos := s.fset.Position(fd.Pos())
	relPos, _ := filepath.Rel(s.root, pos.Filename)
	s.cands[key] = &candidate{Key: key, Pkg: strings.TrimPrefix(pkgPath, modulePath+"/"), Name: fd.Name.Name,
		Pos: fmt.Sprintf("%s:%d", relPos, pos.Line), Params: params, Score: score}
}

// registryEdges adds the approximate func-value edges: reading a
// package-level variable reaches whoever assigns it (CISRules = buildRules()
// makes every Check closure reachable from ruleByID), and naming a module
// function as a value reaches it.
func (s *scanner) registryEdges(fd *ast.FuncDecl, info *types.Info, key string) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if id, ok := ast.Unparen(l).(*ast.Ident); ok {
					if v := pkgVarKey(info.Uses[id]); v != "" {
						s.addEdge(v, key)
					}
				}
			}
		case *ast.Ident:
			if v := pkgVarKey(info.Uses[x]); v != "" {
				s.addEdge(key, v)
			} else if f, ok := info.Uses[x].(*types.Func); ok && f.Pkg() != nil && strings.HasPrefix(f.Pkg().Path(), modulePath) {
				s.addEdge(key, funcKey(f.Origin()))
			}
		}
		return true
	})
}

// recordCall counts one call site and reports whether the callee is a
// parsing primitive.
func (s *scanner) recordCall(info *types.Info, ce *ast.CallExpr, callee *types.Func, key, pkgPath string) bool {
	ck := funcKey(callee)
	s.calls[ck]++
	cp := ""
	if callee.Pkg() != nil {
		cp = callee.Pkg().Path()
	}
	switch {
	case strings.HasPrefix(cp, modulePath):
		s.addEdge(key, ck)
	case callee.Exported() && (isThirdParty(cp) || decoderPkgs[cp]) && takesText(info, ce):
		e := s.ext[ck]
		if e == nil {
			e = &extCall{Key: ck, Path: cp, Pkgs: map[string]bool{}}
			s.ext[ck] = e
		}
		e.Calls++
		e.Pkgs[strings.TrimPrefix(pkgPath, modulePath+"/")] = true
	}
	return primitives[pkgFunc(callee)]
}

// rank marks fuzz coverage and returns the candidates sorted by call sites.
func (s *scanner) rank(roots map[string]bool) []*candidate {
	// Direct: the candidate's name is called from a fuzz file of its own
	// package, or as pkg.Name from any fuzz file.
	for _, c := range s.cands {
		pkg := c.Pkg
		if pkg == modulePath { // fuzzRoots names the root package "."
			pkg = "."
		}
		pkgName := c.Pkg[strings.LastIndex(c.Pkg, "/")+1:]
		if roots[pkg+"\x00"+c.Name] || roots["*\x00"+pkgName+"."+c.Name] {
			c.Direct = true
		}
	}
	// Transitive: reachable in the graph from any module function that a
	// fuzz file calls by name.
	var queue []string
	for caller := range s.graph {
		if fuzzCalled(roots, caller) {
			queue = append(queue, caller)
		}
	}
	for k, c := range s.cands {
		if c.Direct {
			queue = append(queue, k)
		}
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		if seen[k] {
			continue
		}
		seen[k] = true
		for callee := range s.graph[k] {
			queue = append(queue, callee)
		}
	}
	all := make([]*candidate, 0, len(s.cands))
	for k, c := range s.cands {
		c.Calls = s.calls[k]
		c.Transitiv = !c.Direct && seen[k]
		all = append(all, c)
	}
	slices.SortFunc(all, func(a, b *candidate) int {
		return cmp.Or(cmp.Compare(b.Calls, a.Calls), cmp.Compare(b.Score, a.Score), cmp.Compare(a.Key, b.Key))
	})
	return all
}

func printCandidates(w io.Writer, all []*candidate, goos string, top int) {
	direct, trans := 0, 0
	for _, c := range all {
		if c.Direct {
			direct++
		} else if c.Transitiv {
			trans++
		}
	}
	fmt.Fprintf(w, "# reachscan (GOOS=%s)\n\n", goos)
	fmt.Fprintf(w, "parser candidates: %d; fuzz-covered directly: %d; transitively: %d; uncovered: %d\n\n",
		len(all), direct, trans, len(all)-direct-trans)
	fmt.Fprintf(w, "## Top %d parsers without a direct Fuzz target (by production call sites, then parse-primitive count)\n\n", top)
	fmt.Fprintln(w, "reach: `none` = no Fuzz target reaches it statically; `transitive` = only reached")
	fmt.Fprintln(w, "inside a larger target (whole-bundle replay, taint sweep), never fed directly.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| # | function | calls | prims | reach | params | where |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
	n := 0
	for _, c := range all {
		if c.Direct {
			continue
		}
		n++
		if n > top {
			break
		}
		fmt.Fprintf(w, "| %d | `%s.%s` | %d | %d | %s | %s | %s |\n", n, c.Pkg, c.Name, c.Calls, c.Score, c.state(), c.Params, c.Pos)
	}
}

func (c *candidate) state() string {
	switch {
	case c.Direct:
		return "direct"
	case c.Transitiv:
		return "transitive"
	}
	return "none"
}

func printLibraryCalls(w io.Writer, ext map[string]*extCall) {
	exts := slices.Collect(maps.Values(ext))
	slices.SortFunc(exts, func(a, b *extCall) int {
		return cmp.Or(cmp.Compare(b.Calls, a.Calls), cmp.Compare(a.Key, b.Key))
	})
	fmt.Fprintf(w, "\n## Library functions called on text data (third-party, plus stdlib decoders)\n\n")
	fmt.Fprintln(w, "| function | call sites | packages | third-party |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, e := range exts {
		pk := slices.Sorted(maps.Keys(e.Pkgs))
		if len(pk) > 4 {
			pk = append(pk[:4], fmt.Sprintf("+%d", len(e.Pkgs)-4))
		}
		tp := ""
		if isThirdParty(e.Path) {
			tp = "yes"
		}
		fmt.Fprintf(w, "| `%s` | %d | %s | %s |\n", e.Key, e.Calls, strings.Join(pk, ", "), tp)
	}
}

func printAll(w io.Writer, all []*candidate) {
	fmt.Fprintf(w, "\n## All candidates\n\n")
	for _, c := range all {
		fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\n", c.Key, c.Calls, c.Score, c.state(), c.Pos)
	}
}

// pkgVarKey names a package-level variable of this module as a graph node,
// or returns "" for anything else.
func pkgVarKey(obj types.Object) string {
	v, ok := obj.(*types.Var)
	if !ok || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() || !strings.HasPrefix(v.Pkg().Path(), modulePath) {
		return ""
	}
	return "var:" + v.Pkg().Path() + "." + v.Name()
}

func isThirdParty(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return strings.Contains(first, ".") && !strings.HasPrefix(path, modulePath)
}

func funcKey(f *types.Func) string {
	pkg := ""
	if f.Pkg() != nil {
		pkg = f.Pkg().Path()
	}
	if sig, ok := f.Type().(*types.Signature); ok && sig.Recv() != nil {
		t := sig.Recv().Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		if n, ok := t.(*types.Named); ok {
			return pkg + "." + n.Obj().Name() + "." + f.Name()
		}
	}
	return pkg + "." + f.Name()
}

func pkgFunc(f *types.Func) string {
	if f.Pkg() == nil {
		return f.Name()
	}
	return f.Pkg().Path() + "." + f.Name()
}

func calleeFunc(info *types.Info, ce *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch fn := ast.Unparen(ce.Fun).(type) {
	case *ast.Ident:
		id = fn
	case *ast.SelectorExpr:
		id = fn.Sel
	case *ast.IndexExpr: // generic instantiation
		if s, ok := fn.X.(*ast.SelectorExpr); ok {
			id = s.Sel
		} else if i, ok := fn.X.(*ast.Ident); ok {
			id = i
		}
	}
	if id == nil {
		return nil
	}
	f, _ := info.Uses[id].(*types.Func)
	if f != nil {
		f = f.Origin()
	}
	return f
}

// isText reports whether t is one of the shapes untrusted text arrives in.
func isText(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.String
	case *types.Slice:
		if b, ok := u.Elem().Underlying().(*types.Basic); ok {
			return b.Kind() == types.Byte || b.Kind() == types.String
		}
	}
	s := t.String()
	return s == "io.Reader" || s == "*bufio.Scanner" || s == "*bufio.Reader" || s == "io.ReadCloser"
}

func textParams(f *types.Func) (string, bool) {
	sig, _ := f.Type().(*types.Signature)
	if sig == nil {
		return "", false
	}
	var parts []string
	ok := false
	for v := range sig.Params().Variables() {
		parts = append(parts, types.TypeString(v.Type(), func(p *types.Package) string { return p.Name() }))
		if isText(v.Type()) {
			ok = true
		}
	}
	return "(" + strings.Join(parts, ", ") + ")", ok
}

func takesText(info *types.Info, ce *ast.CallExpr) bool {
	for _, a := range ce.Args {
		// Constant arguments (flag names, format layouts) are not data.
		if tv, ok := info.Types[a]; ok && tv.Type != nil && tv.Value == nil && isText(tv.Type) {
			return true
		}
	}
	// Method on a text-carrying value, e.g. re.FindStringSubmatch(s) is
	// covered by the args check; dec.Decode(&v) on a json.Decoder is not text
	// itself but its constructor was counted.
	return false
}

// fuzzRoots returns "pkg\x00Name" for every function name called from a file
// that declares a Fuzz target, plus "*\x00pkgname.Name" for selector calls.
// Every _test.go is read regardless of build tags, since fuzz files for
// other platforms still count as coverage.
func fuzzRoots(root string, dirs []string) map[string]bool {
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		ents, _ := os.ReadDir(dir)
		rel, _ := filepath.Rel(root, dir)
		pkg := filepath.ToSlash(rel)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			af, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
			if err != nil || !hasFuzz(af) {
				continue
			}
			ast.Inspect(af, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := ast.Unparen(ce.Fun).(type) {
				case *ast.Ident:
					out[pkg+"\x00"+fn.Name] = true
				case *ast.SelectorExpr:
					out[pkg+"\x00"+fn.Sel.Name] = true // method on a package value
					if x, ok := fn.X.(*ast.Ident); ok {
						out["*\x00"+x.Name+"."+fn.Sel.Name] = true
					}
				}
				return true
			})
		}
	}
	return out
}

func hasFuzz(af *ast.File) bool {
	for _, d := range af.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && strings.HasPrefix(fd.Name.Name, "Fuzz") && fd.Recv == nil {
			return true
		}
	}
	return false
}

// fuzzCalled reports whether a module function key is called by name from a
// fuzz file of its own package or via pkg.Name.
func fuzzCalled(roots map[string]bool, key string) bool {
	rest := strings.TrimPrefix(key, modulePath)
	rest = strings.TrimPrefix(rest, "/")
	// rest is "internal/collectors.Name" or "internal/collectors.Recv.Name"
	slash := strings.LastIndex(rest, "/")
	dot := strings.Index(rest[slash+1:], ".")
	if dot < 0 {
		return false
	}
	pkg := rest[:slash+1+dot]
	name := rest[slash+1+dot+1:]
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	if strings.HasPrefix(key, modulePath+".") {
		pkg = "."
		name = strings.TrimPrefix(key, modulePath+".")
	}
	pkgName := pkg[strings.LastIndex(pkg, "/")+1:]
	return roots[pkg+"\x00"+name] || roots["*\x00"+pkgName+"."+name]
}
