package cmd

// update_test.go covers cmd/update.go.
//
// confirm() is a pure stdin/stdout function and is fully exercised here.
//
// runUpdate's success paths (isDev/IsNewer/checkOnly/confirm/Apply branches)
// all sit behind selfupdate.LatestRelease, which calls the real GitHub API.
// selfupdate.apiBase is overridable in that package's OWN tests but is an
// unexported var, so it cannot be redirected to a local httptest.Server from
// cmd package tests without editing internal/selfupdate — out of scope for
// this file set. Making a real network call from a unit test is against this
// repo's testing rules, so those branches are intentionally left uncovered
// here (see the "notes" field of the coverage report). The one branch that
// CAN be exercised without real network is the error path: an
// already-canceled context makes net/http fail before any dial/DNS lookup
// (verified: ~50µs, well under any real RTT), so LatestRelease returns
// immediately with "context canceled" and runUpdate's error-wrapping path
// runs for real.

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newBareUpdateCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("check", false, "")
	f.BoolP("yes", "y", false, "")
	return c
}

// Not t.Parallel(): withHookStdin/captureStderr swap shared os.Stdin/os.Stderr.
func TestConfirm(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"yes-short", "y\n", true},
		{"yes-long", "yes\n", true},
		{"yes-uppercase", "Y\n", true},
		{"no", "n\n", false},
		{"empty-line-defaults-no", "\n", false},
		{"garbage", "maybe\n", false},
		{"eof-no-newline", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withHookStdin(t, tt.input)
			var got bool
			out := captureStdout(t, func() { got = confirm("Proceed?") })
			if got != tt.want {
				t.Errorf("confirm(%q) = %v, want %v", tt.input, got, tt.want)
			}
			if !strings.Contains(out, "Proceed?") {
				t.Errorf("expected the prompt echoed, got: %q", out)
			}
		})
	}
}

// TestRunUpdate_LatestReleaseError exercises runUpdate's error-wrapping path
// (selfupdate.LatestRelease failing) without any real network call: an
// already-canceled parent context makes the HTTP client fail immediately.
func TestRunUpdate_LatestReleaseError(t *testing.T) {
	c := newBareUpdateCmd()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.SetContext(ctx)

	err := runUpdate(c, nil)
	if err == nil {
		t.Fatal("expected an error when the update check fails")
	}
	if !strings.Contains(err.Error(), "checking for updates") {
		t.Errorf("expected the error wrapped with context, got: %v", err)
	}
}
