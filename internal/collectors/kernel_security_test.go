package collectors

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseApparmorProfiles(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data string
		want string
	}{
		{
			name: "empty file",
			data: "",
			want: "disabled",
		},
		{
			name: "single enforce profile",
			data: "/usr/sbin/cups-browsed (enforce)\n",
			want: "enforce",
		},
		{
			name: "enforce found first",
			data: "/usr/sbin/sshd (enforce)\n/usr/sbin/cupsd (complain)\n",
			want: "enforce",
		},
		{
			name: "complain only",
			data: "/usr/bin/man (complain)\n",
			want: "complain",
		},
		{
			name: "profiles with no mode suffix",
			data: "some-noise-line\nanother-line\n",
			want: "disabled",
		},
		{
			name: "real ubuntu-like sample",
			data: "lsb_release (enforce)\nman_filter (enforce)\nman_groff (enforce)\nnvidia_modprobe (enforce)\n",
			want: "enforce",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseApparmorProfiles(tc.data)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestApparmorModeFromPath_FileMissing(t *testing.T) {
	t.Parallel()
	got := apparmorModeFromPath("/nonexistent/path/that/does/not/exist")
	if got != "disabled" {
		t.Errorf("missing file should report disabled, got %q", got)
	}
}

func TestApparmorModeFromPath_PermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions semantics differ on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root — cannot test EACCES because root bypasses permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles")
	if err := os.WriteFile(path, []byte("noise (enforce)\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("setup chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	got := apparmorModeFromPath(path)
	if got != "unknown" {
		t.Errorf("EACCES should report unknown, got %q", got)
	}
}

func TestApparmorModeFromPath_Readable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles")
	if err := os.WriteFile(path, []byte("/usr/sbin/sshd (enforce)\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	got := apparmorModeFromPath(path)
	if got != "enforce" {
		t.Errorf("got %q, want enforce", got)
	}
}
