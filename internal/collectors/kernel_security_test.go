package collectors

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakePermDeniedSource reports fs.ErrPermission for one specific path via the
// source seam, regardless of the test process's real uid — root-run test
// suites (e.g. under Docker) cannot exercise EACCES via a real chmod, since
// root bypasses permission bits. This makes the branch deterministically
// reachable independent of the runner's privilege level.
type fakePermDeniedSource struct {
	*source.Replay
	deniedPath string
}

func (f fakePermDeniedSource) ReadFile(path string) ([]byte, error) {
	if path == f.deniedPath {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	return f.Replay.ReadFile(path)
}

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

// TestApparmorModeFromPath_PermissionDenied_ViaSource covers the EACCES branch
// through the source fixture seam, so it runs deterministically even when the
// test process itself is root (e.g. under a Docker-based CI run), unlike
// TestApparmorModeFromPath_PermissionDenied above which self-skips as root.
func TestApparmorModeFromPath_PermissionDenied_ViaSource(t *testing.T) {
	path := "/sys/kernel/security/apparmor/profiles"
	b := source.NewBundle()
	prev := SetSource(fakePermDeniedSource{
		Replay:     source.NewReplay(b),
		deniedPath: path,
	})
	t.Cleanup(func() { SetSource(prev) })

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

// TestApparmorDetail_PermissionDeniedViaSource is the regression guard for
// internal-collectors-18-01: apparmorDetail() must distinguish EACCES (the
// profiles file exists but is root-only, per apparmorMode()'s own comment)
// from "no profiles file at all" — collapsing both to (0,0,0) makes a
// non-root run against a host enforcing hundreds of profiles report
// AppArmorProfiles=0, contradicting AppArmorMode=="unknown" for any raw
// --json consumer that reads the counts without also checking the mode.
func TestApparmorDetail_PermissionDeniedViaSource(t *testing.T) {
	path := "/sys/kernel/security/apparmor/profiles"
	b := source.NewBundle()
	prev := SetSource(fakePermDeniedSource{
		Replay:     source.NewReplay(b),
		deniedPath: path,
	})
	t.Cleanup(func() { SetSource(prev) })

	total, enforce, complain := apparmorDetail()
	if total != -1 || enforce != -1 || complain != -1 {
		t.Errorf("apparmorDetail() on EACCES = (%d, %d, %d), want (-1, -1, -1) sentinel, not zeros", total, enforce, complain)
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
	// permissive=1 means the AVC was logged but NOT enforced (a permissive domain,
	// or global permissive mode) — it blocked nothing, so it must not count toward
	// the denial verdict. Real Fedora CoreOS first-boot bootupd_t line.
	permissive := `type=AVC msg=audit(1715000000.018:107): avc:  denied  { search } for  pid=1479 comm="lsblk" name="mount" dev="tmpfs" ino=400 scontext=system_u:system_r:bootupd_t:s0 tcontext=system_u:object_r:mount_var_run_t:s0 tclass=dir permissive=1`
	if isRecentAVCDenial(permissive, before) {
		t.Error("a permissive=1 AVC (logged, not enforced) must NOT count as a denial")
	}
	// Same record but enforced (permissive=0) must still count.
	enforced := strings.Replace(permissive, "permissive=1", "permissive=0", 1)
	if !isRecentAVCDenial(enforced, before) {
		t.Error("an enforced (permissive=0) AVC denial must count")
	}
	// No "." in the audit(...) timestamp at all — dotIdx < 0.
	noDot := `type=AVC msg=audit(1715000000:460): avc:  denied  { read } for  pid=1 comm="x" tclass=file`
	if isRecentAVCDenial(noDot, before) {
		t.Error("a msg=audit timestamp with no '.' separator must NOT count")
	}
	// "." as the very first character — dotIdx == 0, hits the `dotIdx <= 0` guard.
	dotAtStart := `type=AVC msg=audit(.123:461): avc:  denied  { read } for  pid=1 comm="x" tclass=file`
	if isRecentAVCDenial(dotAtStart, before) {
		t.Error("a msg=audit timestamp with '.' as the first character must NOT count")
	}
	// Non-numeric seconds component — strconv.ParseInt must fail.
	nonNumeric := `type=AVC msg=audit(notanumber.123:462): avc:  denied  { read } for  pid=1 comm="x" tclass=file`
	if isRecentAVCDenial(nonNumeric, before) {
		t.Error("a msg=audit timestamp with non-numeric seconds must NOT count")
	}
}
