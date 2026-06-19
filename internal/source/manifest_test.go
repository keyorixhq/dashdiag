package source

import "testing"

func TestManifestPlatformFamily(t *testing.T) {
	cases := []struct {
		name string
		m    Manifest
		want string
	}{
		{"explicit goos wins", Manifest{GOOS: "linux", OS: "macOS 14"}, "linux"},
		{"explicit darwin", Manifest{GOOS: "darwin"}, "darwin"},
		{"infer ubuntu -> linux", Manifest{OS: "Ubuntu 24.04 LTS"}, "linux"},
		{"infer rhel -> linux", Manifest{OS: "Red Hat Enterprise Linux 9.4"}, "linux"},
		{"infer macos -> darwin", Manifest{OS: "macOS 14.5"}, "darwin"},
		{"infer mac os -> darwin", Manifest{OS: "Mac OS X"}, "darwin"},
		{"infer darwin string -> darwin", Manifest{OS: "Darwin Kernel"}, "darwin"},
		{"infer windows -> windows", Manifest{OS: "Windows Server 2022"}, "windows"},
		{"empty defaults to linux", Manifest{}, "linux"},
	}
	for _, c := range cases {
		if got := c.m.PlatformFamily(); got != c.want {
			t.Errorf("%s: PlatformFamily() = %q, want %q", c.name, got, c.want)
		}
	}
}
