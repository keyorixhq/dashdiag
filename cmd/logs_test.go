package cmd

import "testing"

func TestFormatAgeMin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		min  int
		want string
	}{
		{-1, ""},      // unknown
		{0, "0m ago"}, // just now
		{45, "45m ago"},
		{59, "59m ago"},
		{60, "1h ago"},
		{179, "2h ago"},
		{1439, "23h ago"},
		{1440, "1d ago"},
		{4320, "3d ago"},
	}
	for _, c := range cases {
		if got := formatAgeMin(c.min); got != c.want {
			t.Errorf("formatAgeMin(%d) = %q, want %q", c.min, got, c.want)
		}
	}
}
