package cmd

// wontfix_spec_test.go — specification tests for adversarial-review findings
// closed WONT_FIX (VERIFICATION-2026-08.md §8). These do not hunt for bugs;
// they pin a DECIDED behaviour so it can't drift or get "fixed" by someone
// who doesn't know it was a deliberate call. If one of these fails, either
// the behaviour drifted or the decision changed — revisit the decision (see
// the finding ID in the doc) before touching the code to make it pass.
//
// Not every WONT_FIX finding needs a new test here: sanitize-bundle-03's MCP
// disclosure (TestToolCaptureUnsanitizedDisclosesNote/
// TestToolCaptureIdentifiersImpliesSanitize in mcp_test.go) and
// internal-share-01-02's decode disclaimer (TestRunDecode_
// JSONDisclosesUnverifiedAuthenticity and its text-mode sibling in
// decode_test.go) already assert the decided behaviour precisely — added by
// PR #1008 alongside the mechanism itself. Duplicating them here would just
// be two names for the same guard.

import "testing"

// TestSpec_CMD0902_SafeBundlePathAllowsAbsolutePaths: cmd-09-02 was closed
// WONT_FIX because safeBundlePath's own doc comment already documents this as
// an accepted risk, not an oversight — dsd mcp is stdio-only and its caller is
// a trusted local process, so any absolute (or relative) path is allowed; the
// only thing rejected is a ".." traversal component that could escape an
// expected directory. This test asserts that decided behaviour. If it fails,
// either the behaviour drifted or the decision changed — do not "fix" it
// (e.g. by confining paths to a base directory) without revisiting the
// decision.
func TestSpec_CMD0902_SafeBundlePathAllowsAbsolutePaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"absolute path outside any expected dir is allowed", "/etc/passwd", false},
		{"absolute path with deep unrelated tree is allowed", "/var/lib/somewhere/else/bundle.tar.gz", false},
		{"relative path is allowed", "bundle.tar.gz", false},
		{"traversal component is rejected", "../etc/passwd", true},
		{"traversal component mid-path is rejected", "a/../../b", true},
		{"empty path is rejected", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := safeBundlePath(c.raw)
			if c.wantErr && err == nil {
				t.Errorf("safeBundlePath(%q) = nil error, want an error (traversal/empty must be rejected)", c.raw)
			}
			if !c.wantErr && err != nil {
				t.Errorf("safeBundlePath(%q) = %v, want nil — absolute/relative paths without \"..\" are the accepted-risk case (see safeBundlePath's doc comment)", c.raw, err)
			}
		})
	}
}
