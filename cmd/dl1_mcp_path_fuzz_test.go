package cmd

// DL1 target 2 — the MCP path-validation boundary.
//
// `dsd mcp` exposes five read-only tools over JSON-RPC. The transport is local
// stdio, but the ARGUMENTS are not trusted: in agentic use a path argument
// (dsd_capture out_path, dsd_replay/dsd_diff bundle paths, dsd_share from_path)
// is LLM-generated from documents the model read, which can include
// prompt-injected content. safeBundlePath is the one gate those paths pass
// through; it is the function that keeps a tool call from reading or WRITING
// outside the current working directory — i.e. it is the MCP enforcement point
// of the read-only / no-escape claim.
//
// INVARIANT (cmd, DL1): with the default policy (mcpAllowAbsolutePaths == false),
// every path safeBundlePath ACCEPTS, resolved the way a tool handler resolves it
// (absolute as-is, else joined onto the cwd), is lexically inside the cwd subtree
// — equal to the cwd or under cwd/. No accepted path contains a ".." element, and
// the function never panics, over-allocates or hangs on any input (NUL bytes,
// invalid UTF-8, megabyte paths, many separators).
//
// The oracle re-derives containment INDEPENDENTLY of safeBundlePath's own check
// (it recomputes filepath.Clean(resolve(result)) and tests the prefix itself),
// so a logic bug that lets the function's own guard pass while the path still
// escapes would be caught.
//
// Red-proof: temporarily returning `cleaned, nil` before the cwd check (i.e.
// deleting the escape guard) makes an absolute "/etc/shadow" pass and the
// containment oracle fire — documented in the report, not committed.
//
// Does NOT verify: symlink resolution — safeBundlePath intentionally does NOT
// call EvalSymlinks (documented: blast radius is bounded to the cwd subtree the
// agent's other file tools already reach, not to the symlink target), so a
// symlink UNDER cwd pointing outside is accepted by design and this oracle does
// not flag it. It does not verify the --allow-absolute-paths (operator opt-in)
// branch, where escaping the cwd is the intended behaviour. It does not exercise
// the JSON-RPC decode layer (owned by the go-sdk) or the tool handlers' own I/O.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

func FuzzMCPSafeBundlePathContainment(f *testing.F) {
	seeds := []string{
		"bundle.tar.gz",
		"sub/dir/bundle.tar.gz",
		"./bundle",
		"../escape",
		"../../etc/passwd",
		"/etc/shadow",
		"/abs/outside",
		"a/../../../etc",
		"foo..bar",       // ".." as a substring, not a traversal element
		"a//b/./c",       // redundant separators / dot elements
		"",               // empty — must be rejected
		"nul\x00byte",    // embedded NUL
		"bad\xff\xfeutf", // invalid UTF-8
		strings.Repeat("a/", 1000) + "deep",
		strings.Repeat("../", 500) + "x",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		// Pin the default (constraining) policy for the security oracle.
		mcpAllowAbsolutePaths = false

		n := len(raw)
		var result string
		var err error
		resource.Check(t, n, 64, func() {
			result, err = safeBundlePath(raw)
		})
		if err != nil {
			return // rejected — nothing escaped
		}

		// An accepted path must never carry a ".." element.
		for _, seg := range strings.Split(filepath.ToSlash(result), "/") {
			if seg == ".." {
				t.Fatalf("safeBundlePath accepted %q but result %q contains a '..' element", raw, result)
			}
		}

		// Independently re-derive containment the way a handler resolves the path.
		cwd := mustGetwd(t)
		resolved := result
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(cwd, resolved)
		}
		resolved = filepath.Clean(resolved)
		if resolved != cwd && !strings.HasPrefix(resolved, cwd+string(filepath.Separator)) {
			t.Fatalf("read-only/no-escape violated: safeBundlePath accepted %q → %q, which resolves to %q OUTSIDE cwd %q",
				raw, result, resolved, cwd)
		}
	})
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("cannot resolve cwd: %v", err)
	}
	return cwd
}
