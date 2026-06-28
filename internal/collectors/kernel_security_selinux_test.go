package collectors

import "testing"

// parseSELinuxEnforce maps the world-readable /sys/fs/selinux/enforce node — the
// privilege-independent source that replaced the getenforce-only probe (which was
// absent in Leap Micro's non-root PATH, causing a false "not enforced").
func TestParseSELinuxEnforce(t *testing.T) {
	cases := map[string]string{
		"1":       "enforcing",
		"1\n":     "enforcing",
		" 1 ":     "enforcing",
		"0":       "permissive",
		"0\n":     "permissive",
		"":        "",
		"2":       "",
		"garbage": "",
	}
	for in, want := range cases {
		if got := parseSELinuxEnforce(in); got != want {
			t.Errorf("parseSELinuxEnforce(%q) = %q, want %q", in, got, want)
		}
	}
}
