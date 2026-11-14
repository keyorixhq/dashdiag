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
//   - Dynamic calls. Calls through interfaces, func values and method values
//     are not followed, so "transitive" coverage is a lower bound and a
//     function reached only that way shows as uncovered.
//   - Fuzz coverage is name-based: a candidate is "direct" when its name is
//     called from a file that declares a Fuzz target in the same package (or
//     through pkg.Name from any fuzz file). Name collisions can overstate it.
//   - One GOOS per run. Files excluded by build tags for that GOOS are not
//     scanned; run once per platform for the full picture.
package main

import (
	"cmp"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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

func main() {
	root := flag.String("root", ".", "module root")
	goos := flag.String("goos", "linux", "GOOS to evaluate build tags for")
	top := flag.Int("top", 40, "rows in the uncovered ranking")
	flag.Parse()

	build.Default.GOOS = *goos
	build.Default.CgoEnabled = false

	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil)

	cands := map[string]*candidate{}
	calls := map[string]int{}             // qualified callee -> production call sites
	graph := map[string]map[string]bool{} // caller key -> callee keys (module only)
	ext := map[string]*extCall{}
	var dirs []string
	_ = filepath.WalkDir(*root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		n := d.Name()
		if p != *root && (strings.HasPrefix(n, ".") || n == "testdata" || n == "vendor" || n == "node_modules" ||
			n == "scripts" || n == "testutil") {
			return filepath.SkipDir
		}
		dirs = append(dirs, p)
		return nil
	})

	for _, dir := range dirs {
		bp, err := build.Default.ImportDir(dir, 0)
		if err != nil || len(bp.GoFiles) == 0 {
			continue
		}
		rel, _ := filepath.Rel(*root, dir)
		pkgPath := modulePath
		if rel != "." {
			pkgPath += "/" + filepath.ToSlash(rel)
		}
		var files []*ast.File
		for _, f := range bp.GoFiles {
			af, err := parser.ParseFile(fset, filepath.Join(dir, f), nil, parser.SkipObjectResolution)
			if err == nil {
				files = append(files, af)
			}
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
		conf := types.Config{Importer: imp, Error: func(error) {}}
		_, _ = conf.Check(pkgPath, fset, files, info)

		for _, af := range files {
			for _, decl := range af.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				obj, _ := info.Defs[fd.Name].(*types.Func)
				if obj == nil {
					continue
				}
				key := funcKey(obj)
				score := 0
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					callee := calleeFunc(info, ce)
					if callee == nil {
						return true
					}
					ck := funcKey(callee)
					calls[ck]++
					if primitives[pkgFunc(callee)] {
						score++
					}
					cp := ""
					if callee.Pkg() != nil {
						cp = callee.Pkg().Path()
					}
					switch {
					case strings.HasPrefix(cp, modulePath):
						if graph[key] == nil {
							graph[key] = map[string]bool{}
						}
						graph[key][ck] = true
					case callee.Exported() && (isThirdParty(cp) || decoderPkgs[cp]) && takesText(info, ce):
						e := ext[ck]
						if e == nil {
							e = &extCall{Key: ck, Path: cp, Pkgs: map[string]bool{}}
							ext[ck] = e
						}
						e.Calls++
						e.Pkgs[strings.TrimPrefix(pkgPath, modulePath+"/")] = true
					}
					return true
				})
				params, textual := textParams(obj)
				if !textual {
					continue
				}
				if !parseNameRe.MatchString(fd.Name.Name) && score < 3 {
					continue
				}
				pos := fset.Position(fd.Pos())
				relPos, _ := filepath.Rel(*root, pos.Filename)
				cands[key] = &candidate{Key: key, Pkg: strings.TrimPrefix(pkgPath, modulePath+"/"), Name: fd.Name.Name,
					Pos: fmt.Sprintf("%s:%d", relPos, pos.Line), Params: params, Score: score}
			}
		}
	}

	roots := fuzzRoots(*root, dirs)
	// Direct: the candidate's name is called from a fuzz file of its own
	// package, or as pkg.Name from any fuzz file.
	for _, c := range cands {
		pkgName := c.Pkg[strings.LastIndex(c.Pkg, "/")+1:]
		if roots[c.Pkg+"\x00"+c.Name] || roots["*\x00"+pkgName+"."+c.Name] {
			c.Direct = true
		}
	}
	// Transitive: reachable in the static call graph from any module function
	// that a fuzz file calls by name.
	seen := map[string]bool{}
	var queue []string
	for caller := range graph {
		if fuzzCalled(roots, caller) {
			queue = append(queue, caller)
		}
	}
	for k, c := range cands {
		if c.Direct {
			queue = append(queue, k)
		}
	}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		if seen[k] {
			continue
		}
		seen[k] = true
		for callee := range graph[k] {
			queue = append(queue, callee)
		}
	}
	var all []*candidate
	for k, c := range cands {
		c.Calls = calls[k]
		if !c.Direct && seen[k] {
			c.Transitiv = true
		}
		all = append(all, c)
	}
	slices.SortFunc(all, func(a, b *candidate) int {
		return cmp.Or(cmp.Compare(b.Calls, a.Calls), cmp.Compare(b.Score, a.Score), cmp.Compare(a.Key, b.Key))
	})

	direct, trans := 0, 0
	for _, c := range all {
		if c.Direct {
			direct++
		} else if c.Transitiv {
			trans++
		}
	}
	fmt.Printf("# reachscan (GOOS=%s)\n\n", *goos)
	fmt.Printf("parser candidates: %d; fuzz-covered directly: %d; transitively: %d; uncovered: %d\n\n",
		len(all), direct, trans, len(all)-direct-trans)
	fmt.Printf("## Top %d parsers without a direct Fuzz target (by production call sites, then parse-primitive count)\n\n", *top)
	fmt.Println("reach: `none` = no Fuzz target reaches it statically; `transitive` = only reached")
	fmt.Println("inside a larger target (whole-bundle replay, taint sweep), never fed directly.")
	fmt.Println()
	fmt.Println("| # | function | calls | prims | reach | params | where |")
	fmt.Println("|---|---|---|---|---|---|---|")
	n := 0
	for _, c := range all {
		if c.Direct {
			continue
		}
		n++
		if n > *top {
			break
		}
		reach := "none"
		if c.Transitiv {
			reach = "transitive"
		}
		fmt.Printf("| %d | `%s.%s` | %d | %d | %s | %s | %s |\n", n, c.Pkg, c.Name, c.Calls, c.Score, reach, c.Params, c.Pos)
	}

	var exts []*extCall
	for _, e := range ext {
		exts = append(exts, e)
	}
	slices.SortFunc(exts, func(a, b *extCall) int {
		return cmp.Or(cmp.Compare(b.Calls, a.Calls), cmp.Compare(a.Key, b.Key))
	})
	fmt.Printf("\n## Library functions called on text data (third-party, plus stdlib decoders)\n\n")
	fmt.Println("| function | call sites | packages | third-party |")
	fmt.Println("|---|---|---|---|")
	for _, e := range exts {
		pk := slices.Sorted(mapKeys(e.Pkgs))
		if len(pk) > 4 {
			pk = append(pk[:4], fmt.Sprintf("+%d", len(e.Pkgs)-4))
		}
		tp := ""
		if isThirdParty(e.Path) {
			tp = "yes"
		}
		fmt.Printf("| `%s` | %d | %s | %s |\n", e.Key, e.Calls, strings.Join(pk, ", "), tp)
	}

	if os.Getenv("REACHSCAN_ALL") != "" {
		fmt.Printf("\n## All candidates\n\n")
		for _, c := range all {
			state := "uncovered"
			if c.Direct {
				state = "direct"
			} else if c.Transitiv {
				state = "transitive"
			}
			fmt.Printf("%s\t%d\t%d\t%s\t%s\n", c.Key, c.Calls, c.Score, state, c.Pos)
		}
	}
}

func mapKeys(m map[string]bool) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
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
