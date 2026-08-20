package init_pkg

// wontfix_spec_test.go — specification test for a finding closed WONT_FIX in
// the adversarial review (VERIFICATION-2026-08.md §8). Pins a DECIDED
// behaviour, not a bug hunt. If it fails, either the behaviour drifted or the
// decision changed — revisit the decision before "fixing" the code.
//
// The other half of this finding's reasoning — that a suggested profile is
// never acted on without interactive human confirmation, which is why
// hardening the detection heuristic further has diminishing value — is
// already asserted by TestRunWizard_ValidSelectionWritesConfig and
// TestRunWizard_EOFStdinNoOp in firstrun_test.go: both show writeProfileConfig
// is reached only after tui.RunSingleSelect returns an actual selection,
// never from DetectServerProfile's guess alone. Not duplicated here.

import "testing"

// TestSpec_InternalInit0103_ClassifyProfileTrustsUnverifiedCommName:
// internal-init-01-03 was closed WONT_FIX because RunWizard already requires
// interactive human confirmation before any suggested profile is written —
// a real mitigation already in place, making further hardening of the
// detection heuristic itself low value (see VERIFICATION-2026-08.md §8).
// Pending any future decision, classifyProfile trusts /proc/<pid>/comm (or,
// on macOS, ps's reported command name) at face value: any process that
// simply NAMES itself "nginx" — trivial for anything running as the same
// user, no privilege required — is classified "web" exactly like a genuine
// nginx install. This test documents that accepted gap. It must not start
// verifying process identity (e.g. checking the binary path, checksums, or
// anything beyond the reported name) without the decision being revisited —
// that would change classification behaviour this decision left alone on
// purpose, on the reasoning that the human-confirmation gate downstream
// already covers it.
func TestSpec_InternalInit0103_ClassifyProfileTrustsUnverifiedCommName(t *testing.T) {
	t.Parallel()
	// A process that merely reports the name "nginx" — e.g. `cp /bin/true
	// /tmp/nginx && /tmp/nginx`, or any binary renamed via argv[0] — is
	// indistinguishable to classifyProfile from a genuine nginx install. It
	// only ever sees the reported comm name, never the binary's real identity.
	impersonator := []string{"bash", "sshd", "nginx"} // "nginx" here is any process self-reporting that name
	if got := classifyProfile(impersonator); got != "web" {
		t.Errorf(`classifyProfile(%v) = %q, want "web" — a process self-reporting the name "nginx" is `+
			`trusted at face value, no verification beyond the name string (internal-init-01-03: accepted `+
			`because RunWizard gates every suggestion behind interactive human confirmation)`, impersonator, got)
	}
}
