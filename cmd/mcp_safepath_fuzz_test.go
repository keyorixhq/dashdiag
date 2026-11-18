package cmd

// mcp_safepath_fuzz_test.go — FuzzSafeBundlePathContainment: differential
// check of safeBundlePath (cmd/mcp.go), the only gate between an LLM-generated
// (prompt-injectable) MCP path argument and a file write/read.
//
// Oracles:
//
//  1. Soundness (differential): any path safeBundlePath accepts in the
//     default mode must be lexically inside CWD according to
//     lexicallyEscapesCWD (filepath.Rel based — a different mechanism from
//     safeBundlePath's own strings.HasPrefix check).
//  2. Idempotence (metamorphic): an accepted path, fed back in, is accepted
//     again and cleans to itself.
//  3. Relative/absolute equivalence (metamorphic): for an accepted relative
//     path p, filepath.Join(cwd, p) is accepted too.
//  4. Unconditional traversal rule: in --allow-absolute-paths mode the
//     result never contains a ".." path element.
//
// What this does NOT verify: symlinks — the check is purely lexical, and an
// accepted path whose directory component is a symlink to outside CWD is a
// separate, reproduced finding (TestReproSafeBundlePathDirSymlinkEscape);
// case-insensitive filesystems (macOS APFS default) where two lexically
// different paths name the same file; over-rejection (a name like "a..b" is
// refused although it is local — fail-closed, not checked as a defect);
// Windows volume/UNC semantics (fuzzed on darwin/linux only).

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func FuzzSafeBundlePathContainment(f *testing.F) {
	for _, s := range []string{
		"x.tar.gz", "./x", "a/b/c", "/etc/passwd", "..", "../x", "a/../../x",
		"a..b", "/", ".", "//x", "a//b/", "\x00", "a/./../b",
		"/tmp/../etc", "~/.ssh/id_rsa", "C:\\x", "a\\..\\..\\x",
	} {
		f.Add(s, false)
	}
	cwd, err := os.Getwd()
	if err == nil {
		f.Add(cwd, false)
		f.Add(cwd+"x/../../y", false)
		f.Add(cwd+"/sub", false)
		f.Add(cwd+"-sibling/x", false)
	}

	f.Fuzz(func(t *testing.T, raw string, allowAbs bool) {
		prev := mcpAllowAbsolutePaths
		mcpAllowAbsolutePaths = allowAbs
		defer func() { mcpAllowAbsolutePaths = prev }()

		cleaned, err := safeBundlePath(raw)
		if err != nil {
			return
		}
		if allowAbs {
			if slices.Contains(strings.Split(filepath.ToSlash(cleaned), "/"), "..") {
				t.Fatalf("allow-absolute mode returned a traversal path: %q -> %q", raw, cleaned)
			}
			return
		}
		if v := lexicallyEscapesCWD(cleaned); v != "" {
			t.Fatalf("containment: safeBundlePath(%q) = %q accepted, but it %s", raw, cleaned, v)
		}
		again, err := safeBundlePath(cleaned)
		if err != nil || again != cleaned {
			t.Fatalf("idempotence: safeBundlePath(%q)=%q, then safeBundlePath(%q)=(%q, %v)", raw, cleaned, cleaned, again, err)
		}
		if !filepath.IsAbs(cleaned) {
			wd, werr := os.Getwd()
			if werr != nil {
				return
			}
			if _, err := safeBundlePath(filepath.Join(wd, cleaned)); err != nil {
				t.Fatalf("rel/abs equivalence: %q accepted but its absolute form is rejected: %v", cleaned, err)
			}
		}
	})
}
