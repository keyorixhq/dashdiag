package main

import (
	"bytes"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture is a small module tree: one package with parsers that are fuzzed
// directly, reached only through the call graph or a registry variable, or
// not reached at all, plus a root package and directories reachscan skips.
var fixture = map[string]string{
	"root.go": `package root

import "strings"

func ParseRoot(s string) []string { return rootHelper(strings.Fields(s)) }

func rootHelper(f []string) []string { return f }
`,
	"root_fuzz_test.go": `package root

import "testing"

func FuzzRoot(fz *testing.F) { fz.Fuzz(func(t *testing.T, s string) { ParseRoot(s) }) }
`,
	"p/p.go": `package p

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type rule struct{ check func(string) bool }

var Registry []rule

func setup() { Registry = buildRegistry() }

func buildRegistry() []rule { return []rule{{check: checkLine}} }

// checkLine is not parser-named; three primitives make it a candidate.
func checkLine(s string) bool {
	f := strings.Fields(s)
	_, err := strconv.Atoi(f[0])
	return err == nil && strings.HasPrefix(s, "x")
}

func RuleByID(s string) bool { return Registry[0].check(s) }

func ParseDirect(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func ParseViaGraph(s string) int { return helperParse(s) }

func helperParse(s string) int { return len(strings.Split(s, ",")) }

func ParseUncovered(r io.Reader) int {
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
	}
	return n
}

func Caller(r io.Reader) int { setup(); return ParseUncovered(r) + ParseUncovered(r) }

type Dec struct{}

func (d *Dec) DecodeLine(b []byte) string { return string(b) }

func Map[T any](x T) T { return x }

func useGeneric(s string) string { return Map[string](s) + Map(s) }

func Match(s string) bool {
	re := regexp.MustCompile("a+")
	return re.MatchString(s)
}

func ParseInt(n int) int { return n }
`,
	"p/fuzz_test.go": `package p

import "testing"

func FuzzP(fz *testing.F) {
	fz.Fuzz(func(t *testing.T, s string) {
		ParseDirect(s)
		ParseViaGraph(s)
		RuleByID(s)
		d := &Dec{}
		d.DecodeLine([]byte(s))
	})
}
`,
	"p/plain_test.go": `package p

import "testing"

func TestPlain(t *testing.T) { ParseUncovered(nil) }
`,
	// Skipped trees and unparsable files must not abort the scan.
	"p/testdata/bad.go":        "package bad\nfunc ParseBad(s string) {",
	"scripts/tool/tool.go":     "package tool\nfunc ParseTool(s string) int { return len(s) }\n",
	".hidden/h.go":             "package h\nfunc ParseHidden(s string) int { return len(s) }\n",
	"e/broken_fuzz_test.go":    "package e\nfunc FuzzE(",
	"docs/README.md":           "not go",
	"q/q_linux.go":             "package q\nfunc ParseLinuxOnly(s string) int { return len(s) }\n",
	"q/q_windows_only_test.go": "package q\n",
}

func writeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range fixture {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestRun scans the fixture once per GOOS. Subtests run sequentially because
// run sets build.Default.GOOS for the source importer.
func TestRun(t *testing.T) {
	t.Parallel()
	root := writeFixture(t)

	t.Run("linux", func(t *testing.T) {
		var out bytes.Buffer
		if err := run([]string{"-root", root, "-goos", "linux", "-top", "40", "-all"}, &out); err != nil {
			t.Fatal(err)
		}
		got := out.String()
		for _, want := range []string{
			"# reachscan (GOOS=linux)",
			"| `p.ParseUncovered` | 2 | 1 | none | (io.Reader) |",
			"| `p.helperParse` | 1 | 1 | transitive |",
			"| `p.checkLine` | 0 | 3 | transitive |",
			"`q.ParseLinuxOnly`",
			"| `regexp.Regexp.MatchString` | 1 | p |  |",
			"## All candidates",
			"github.com/keyorixhq/dashdiag/p.ParseDirect\t0\t2\tdirect\t",
			"github.com/keyorixhq/dashdiag/p.Dec.DecodeLine\t0\t0\tdirect\t",
			"github.com/keyorixhq/dashdiag.ParseRoot\t0\t1\tdirect\t",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("output missing %q\n%s", want, got)
			}
		}
		for _, absent := range []string{"ParseBad", "ParseTool", "ParseHidden", "p.ParseInt", "useGeneric", "p.Match\t"} {
			if strings.Contains(got, absent) {
				t.Errorf("output unexpectedly contains %q\n%s", absent, got)
			}
		}
	})

	t.Run("darwin top 1", func(t *testing.T) {
		var out bytes.Buffer
		if err := run([]string{"-root", root, "-goos", "darwin", "-top", "1", "-all=false"}, &out); err != nil {
			t.Fatal(err)
		}
		got := out.String()
		if strings.Contains(got, "ParseLinuxOnly") {
			t.Errorf("linux-only file scanned for darwin\n%s", got)
		}
		if strings.Contains(got, "| 2 | `") || strings.Contains(got, "## All candidates") {
			t.Errorf("-top 1 -all=false printed more than one ranked row or the full list\n%s", got)
		}
	})

	// A -trimpath build leaves GOROOT empty; run must recover it, and must
	// refuse to report when the standard library still cannot be loaded.
	t.Run("GOROOT", func(t *testing.T) {
		saved := build.Default.GOROOT
		defer func() { build.Default.GOROOT = saved }()

		build.Default.GOROOT = ""
		var out bytes.Buffer
		if err := run([]string{"-root", root}, &out); err != nil {
			t.Fatalf("empty GOROOT not recovered: %v", err)
		}
		if !strings.Contains(out.String(), "`strconv.Atoi`") {
			t.Errorf("stdlib calls missing after GOROOT recovery\n%s", out.String())
		}

		build.Default.GOROOT = t.TempDir()
		if err := run([]string{"-root", root}, &out); err == nil {
			t.Fatal("want error when the standard library cannot be imported")
		}
	})

	t.Run("bad flag", func(t *testing.T) {
		var out bytes.Buffer
		if err := run([]string{"-nope"}, &out); err == nil {
			t.Fatal("want error for unknown flag")
		}
	})
}

func TestPrintLibraryCalls(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	printLibraryCalls(&out, map[string]*extCall{
		"example.com/y.Load": {Key: "example.com/y.Load", Path: "example.com/y", Calls: 7,
			Pkgs: map[string]bool{"a": true, "b": true, "c": true, "d": true, "e": true, "f": true}},
		"strconv.Atoi": {Key: "strconv.Atoi", Path: "strconv", Calls: 1, Pkgs: map[string]bool{"a": true}},
	})
	got := out.String()
	for _, want := range []string{
		"| `example.com/y.Load` | 7 | a, b, c, d, +2 | yes |",
		"| `strconv.Atoi` | 1 | a |  |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n%s", want, got)
		}
	}
	if strings.Index(got, "example.com/y.Load") > strings.Index(got, "strconv.Atoi") {
		t.Errorf("rows not sorted by call count\n%s", got)
	}
}

func TestIsThirdParty(t *testing.T) {
	t.Parallel()
	for path, want := range map[string]bool{
		"gopkg.in/yaml.v3":                      true,
		"github.com/spf13/viper":                true,
		"strconv":                               false,
		"encoding/json":                         false,
		"github.com/keyorixhq/dashdiag/p":       false,
		"github.com/keyorixhq/dashdiag/scripts": false,
	} {
		if got := isThirdParty(path); got != want {
			t.Errorf("isThirdParty(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestFuzzCalledDotless(t *testing.T) {
	t.Parallel()
	if fuzzCalled(map[string]bool{}, modulePath+"/internal/x") {
		t.Fatal("key without a function name reported as fuzz-called")
	}
}
