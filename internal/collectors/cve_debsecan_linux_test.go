package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestCheckCVEDebsecan guards the false-OK fix: a failed debsecan run must report
// UNKNOWN (exposure not verified), not NOT_AFFECTED. A successful empty result is
// NOT_AFFECTED; package findings are VULNERABLE even on a non-zero (grep-style) exit.
func TestCheckCVEDebsecan(t *testing.T) {
	cases := []struct {
		name string
		res  source.Result
		want models.CVEStatus
	}{
		{"debsecan failed (non-zero, no output)", source.Result{ExitCode: 2}, models.CVEUnknown},
		{"ran clean, no vulns", source.Result{ExitCode: 0}, models.CVENotAffected},
		{"finds a package (non-zero exit)", source.Result{
			Stdout: []byte("CVE-2024-1234 openssl fix-available remote code execution"), ExitCode: 1,
		}, models.CVEVulnerable},
		{
			// Clean exit, non-empty output, but no parseable package rows (e.g. only
			// a comment/header line) — guards the "default" (already patched) branch,
			// distinct from the fully-empty "ran clean, no vulns" case above.
			name: "ran clean, only a comment line",
			res:  source.Result{Stdout: []byte("# debsecan report, no matches\n"), ExitCode: 0},
			want: models.CVEPatched,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := fakeRunSource{run: func(_ string, _ []string) source.Result { return c.res }}
			defer SetSource(SetSource(fake))

			got := checkCVEDebsecan(context.Background(), "CVE-2024-1234", &models.CVEResult{})
			if got.Status != c.want {
				t.Errorf("status = %q, want %q (reason: %q)", got.Status, c.want, got.StatusReason)
			}
		})
	}
}
