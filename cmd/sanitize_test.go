package cmd

import "testing"

func TestSanitizedOutPath(t *testing.T) {
	cases := map[string]string{
		"dsd-raw-host.tar.gz": "dsd-raw-host-sanitized.tar.gz",
		"bundle.tgz":          "bundle-sanitized.tgz",
		"snap.tar":            "snap-sanitized.tar",
		"noext":               "noext-sanitized",
		"/a/b/c.tar.gz":       "/a/b/c-sanitized.tar.gz",
	}
	for in, want := range cases {
		if got := sanitizedOutPath(in); got != want {
			t.Errorf("sanitizedOutPath(%q) = %q, want %q", in, got, want)
		}
	}
}
