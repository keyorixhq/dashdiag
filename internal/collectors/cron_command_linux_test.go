//go:build linux

package collectors

import "testing"

func TestExtractCronCommand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		line         string
		hasUserField bool
		want         string
	}{
		{
			// User crontab whose command starts with a bare word — the old
			// content heuristic misread "backup" as a username and dropped it.
			name:         "user crontab bare-word command",
			line:         "0 2 * * * backup --incremental /data",
			hasUserField: false,
			want:         "backup --incremental /data",
		},
		{
			name:         "user crontab absolute path",
			line:         "*/5 * * * * /usr/bin/refresh --quiet",
			hasUserField: false,
			want:         "/usr/bin/refresh --quiet",
		},
		{
			name:         "system crontab with user column",
			line:         "0 3 * * * root /usr/local/bin/cleanup",
			hasUserField: true,
			want:         "/usr/local/bin/cleanup",
		},
		{
			name:         "too few fields",
			line:         "0 2 * * *",
			hasUserField: false,
			want:         "",
		},
		{
			// Exactly 6 fields (5 time fields + user, no command) passes the
			// len(fields)<6 guard but must still be rejected by the
			// len(fields)<=timeFields check once hasUserField shifts
			// timeFields to 6 — a distinct boundary from the "too few fields"
			// case above.
			name:         "user field present but no command follows",
			line:         "0 3 * * * root",
			hasUserField: true,
			want:         "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := extractCronCommand(tc.line, tc.hasUserField); got != tc.want {
				t.Errorf("extractCronCommand(%q, %v) = %q, want %q", tc.line, tc.hasUserField, got, tc.want)
			}
		})
	}
}
