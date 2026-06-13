package collectors

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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

func TestIsRecentAVCDenial(t *testing.T) {
	// Real-format audit.log lines (the AVC record format is stable). Epoch 1715000000.
	denied := `type=AVC msg=audit(1715000000.123:456): avc:  denied  { read } for  pid=1234 comm="httpd" name="shadow" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`
	granted := `type=AVC msg=audit(1715000000.124:457): avc:  granted  { read } for  pid=1234 comm="trusted" scontext=system_u:system_r:trusted_t:s0 tclass=file`
	userAVC := `type=USER_AVC msg=audit(1715000000.125:458): pid=1 uid=0 auid=4294967295 msg='avc:  denied  { send_msg } for ... '`
	nonAVC := `type=SYSCALL msg=audit(1715000000.126:459): arch=c000003e syscall=2 success=yes`

	before := time.Unix(1714000000, 0) // cutoff well before the events -> they are "recent"
	after := time.Unix(1716000000, 0)  // cutoff well after -> events are "old"

	if !isRecentAVCDenial(denied, before) {
		t.Error("a recent AVC denial must count")
	}
	if isRecentAVCDenial(granted, before) {
		t.Error("an `avc: granted` (auditallow) record must NOT count as a denial")
	}
	if isRecentAVCDenial(denied, after) {
		t.Error("a denial older than the window must NOT count")
	}
	if isRecentAVCDenial(userAVC, before) {
		t.Error("type=USER_AVC is outside the kernel-AVC scope of this counter")
	}
	if isRecentAVCDenial(nonAVC, before) {
		t.Error("a non-AVC audit record must NOT count")
	}
	if isRecentAVCDenial("type=AVC denied but no msg=audit timestamp", before) {
		t.Error("a line without a parseable audit timestamp must NOT count")
	}
}
