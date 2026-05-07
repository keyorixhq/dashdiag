package collectors

import (
	"strings"
	"testing"
)

func TestParseUnitList(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		input     string
		wantUnits []string
	}{
		{
			name:      "single failed unit",
			input:     "nginx.service       loaded failed failed The nginx HTTP server\n",
			wantUnits: []string{"nginx.service"},
		},
		{
			name: "multiple units",
			input: "sshd.service        loaded failed failed OpenSSH server\n" +
				"cron.service        loaded failed failed Cron daemon\n",
			wantUnits: []string{"sshd.service", "cron.service"},
		},
		{
			name:      "empty output",
			input:     "",
			wantUnits: nil,
		},
		{
			name:      "lines without dots are skipped",
			input:     "0 units listed\n",
			wantUnits: nil,
		},
		{
			name:      "blank lines skipped",
			input:     "\nnginx.service loaded failed failed nginx\n\n",
			wantUnits: []string{"nginx.service"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseUnitList(strings.NewReader(tc.input))
			if len(got) != len(tc.wantUnits) {
				t.Fatalf("unit count: got %d %v, want %d %v", len(got), got, len(tc.wantUnits), tc.wantUnits)
			}
			for i, u := range tc.wantUnits {
				if got[i] != u {
					t.Errorf("unit[%d]: got %q, want %q", i, got[i], u)
				}
			}
		})
	}
}
