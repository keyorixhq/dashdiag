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
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := extractCronCommand(tc.line, tc.hasUserField); got != tc.want {
				t.Errorf("extractCronCommand(%q, %v) = %q, want %q", tc.line, tc.hasUserField, got, tc.want)
			}
		})
	}
}
