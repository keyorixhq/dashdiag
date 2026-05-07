package collectors

import (
	"testing"
)

func TestParseSELinuxMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"enforcing uppercase", "Enforcing\n", "enforcing"},
		{"permissive uppercase", "Permissive\n", "permissive"},
		{"disabled uppercase", "Disabled\n", "disabled"},
		{"enforcing lowercase", "enforcing\n", "enforcing"},
		{"with spaces", "  Enforcing  \n", "enforcing"},
		{"empty", "", ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseSELinuxMode(tc.input)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
