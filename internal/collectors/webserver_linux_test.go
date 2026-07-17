//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestFirstConfigError drives firstConfigError directly (rather than only
// transitively via apache/haproxy Collect() tests), covering the blank-line
// skip, each error-marker match, the non-error fallback to the first
// non-empty line, and the fully-empty-input sentinel — branches the existing
// apache/haproxy fixture-driven tests don't happen to exercise.
func TestFirstConfigError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "blank leading lines are skipped, marker line wins",
			out:  "\n\n[emerg] could not open error log file\nsome other line\n",
			want: "[emerg] could not open error log file",
		},
		{
			name: "syntax marker matches case-insensitively",
			out:  "Configuration Syntax OK is a lie\nSYNTAX ERROR on line 4\n",
			want: "Configuration Syntax OK is a lie",
		},
		{
			name: "no marker line — falls back to first non-empty line",
			out:  "\n\n  just some informational text\nmore text\n",
			want: "just some informational text",
		},
		{
			name: "completely empty input — falls back to the sentinel",
			out:  "",
			want: "config test failed",
		},
		{
			name: "only blank lines — falls back to the sentinel",
			out:  "\n\n\n",
			want: "config test failed",
		},
		{
			name: "cannot marker matches",
			out:  "cannot load module foo.so into server\n",
			want: "cannot load module foo.so into server",
		},
		{
			name: "failed marker matches",
			out:  "bind() to 0.0.0.0:80 failed (98: Address already in use)\n",
			want: "bind() to 0.0.0.0:80 failed (98: Address already in use)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := firstConfigError(tt.out); got != tt.want {
				t.Errorf("firstConfigError(%q) = %q, want %q", tt.out, got, tt.want)
			}
		})
	}
}

// TestWebConfigTest_EmptyCommandGuard covers the `if len(c) == 0 { continue }`
// guard in webConfigTest (line 18): an empty command slice in the cmds list is
// silently skipped, not panicked on (c[0] would panic on an empty slice).
func TestWebConfigTest_EmptyCommandGuard(t *testing.T) {
	t.Parallel()
	// cmds has one entry with zero elements; the guard fires and we skip to the
	// end of the loop, returning (false, false, "").
	withFixtureSource(t, func(_ *source.Bundle) {})
	ran, valid, errLine := webConfigTest(context.Background(), [][]string{{}})
	if ran || valid || errLine != "" {
		t.Errorf("empty command must be skipped: ran=%v valid=%v errLine=%q", ran, valid, errLine)
	}
}

// TestWebVersion_EmptyCommandGuard covers the `if len(c) == 0 { continue }`
// guard in webVersion (line 64): an empty command slice is silently skipped,
// and the function returns "" when no command succeeds.
func TestWebVersion_EmptyCommandGuard(t *testing.T) {
	t.Parallel()
	withFixtureSource(t, func(_ *source.Bundle) {})
	if got := webVersion(context.Background(), [][]string{{}}, "Apache/"); got != "" {
		t.Errorf("empty command must be skipped, want empty result, got %q", got)
	}
}
