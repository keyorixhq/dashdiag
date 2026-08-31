package cmd

import (
	"errors"
	"fmt"
	"testing"
)

// C1: "3 = tool error, checks did not run" must be reserved for a run that
// produced NO meaningful verdict at all (a fatal error before any collector
// ran — e.g. an unparseable --policy file) — not for an ordinary Cobra
// dispatch error on some other command (bad flags, unknown subcommand),
// which keeps the long-standing exit 1. Conflating the two would mean a
// single flaky/misused flag on an unrelated command reads as "UNKNOWN",
// which is not what it is.
func TestExitCodeForExecuteError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil is unreachable in practice but must not panic", nil, 1},
		{"ordinary Cobra dispatch error stays exit 1", errors.New("unknown flag: --bogus"), 1},
		{"fatal preflight error maps to exit 3 (UNKNOWN)", fatalPreflight(errors.New("policy file: yaml: line 3: mapping values are not allowed")), 3},
		{"wrapped fatal preflight error still maps to exit 3", fmt.Errorf("running health: %w", fatalPreflight(errors.New("boom"))), 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeForExecuteError(tc.err); got != tc.want {
				t.Errorf("exitCodeForExecuteError(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestFatalPreflightNilIsNil confirms the constructor's nil-passthrough
// (mirrors the fmt.Errorf/errors.New idiom other cmd/ helpers already use —
// a bare `if err != nil { return fatalPreflight(err) }` call site must not
// turn a nil error into a non-nil one.
func TestFatalPreflightNilIsNil(t *testing.T) {
	if err := fatalPreflight(nil); err != nil {
		t.Errorf("fatalPreflight(nil) = %v, want nil", err)
	}
}
