package collectors

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestStatfsToFSRoot exercises the non-blocking statfsToFS happy path: the root
// filesystem must return real numbers within the timeout.
func TestStatfsToFSRoot(t *testing.T) {
	t.Parallel()
	fs, err := statfsToFS(mountEntry{device: "rootdev", mountPoint: "/", fsType: "testfs"})
	if err != nil {
		t.Fatalf("statfsToFS(/): %v", err)
	}
	if fs.Mount != "/" {
		t.Errorf("Mount: got %q, want /", fs.Mount)
	}
	if fs.TotalGB <= 0 {
		t.Errorf("TotalGB: got %v, want > 0", fs.TotalGB)
	}
}

// TestStatfsToFS_TimesOut guards the statfsTimeout deadline branch: a statfs
// call that hangs (a stale/D-state mount) past statfsTimeout must return a
// wrapped timeout error rather than blocking the caller forever. Reuses the
// slowStatfsSource fake from nfs_linux_test.go (same pattern, same package) —
// not a synthetic branch, this drives statfsToFS's own select/time.After path.
func TestStatfsToFS_TimesOut(t *testing.T) {
	prev := SetSource(&slowStatfsSource{Replay: source.NewReplay(source.NewBundle()), delay: 3 * time.Second})
	t.Cleanup(func() { SetSource(prev) })

	_, err := statfsToFS(mountEntry{device: "hungdev", mountPoint: "/mnt/hung", fsType: "nfs"})
	if err == nil {
		t.Fatal("expected a timeout error when statfs exceeds statfsTimeout")
	}
}

// TestLooksLikeHost guards the `w` FROM-vs-LOGIN@ discrimination, including the
// previously-broken case of a bare LAN hostname with no dot.
func TestLooksLikeHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		// Hosts (FROM column present)
		{"192.168.1.5", true},
		{"10.0.0.1", true},
		{"host.example.com", true},
		{"workstation", true}, // dotless LAN hostname — the regression
		{"build-server-01", true},
		{"monitoring", true}, // starts with "mon" but is a host, not Monday
		{"fe80::1", true},    // IPv6
		{"-", true},          // local-login marker — the FROM column IS present (just empty)
		// LOGIN@ timestamps (no FROM column)
		{"", false},
		{"10:00", false},
		{"08:23", false},
		{"9:00am", false},
		{"11:30pm", false},
		{"Mon", false},
		{"Tue08", false},
		{"Wed14", false},
		{"23Jun24", false},
	}
	for _, tc := range cases {
		if got := looksLikeHost(tc.in); got != tc.want {
			t.Errorf("looksLikeHost(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestParseSessionsDotlessRemoteHost is the security regression: a root SSH login
// from a dotless hostname must be classified as remote (RootSSH), not local.
func TestParseSessionsDotlessRemoteHost(t *testing.T) {
	t.Parallel()
	// USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
	out := "root     pts/1    workstation      14:00    1.00s  0.10s  0.05s  -bash\n"
	info := parseSessions(out)

	if len(info.Sessions) != 1 {
		t.Fatalf("session count: got %d, want 1", len(info.Sessions))
	}
	if info.Sessions[0].From != "workstation" {
		t.Errorf("From: got %q, want %q", info.Sessions[0].From, "workstation")
	}
	if !info.RootSSH {
		t.Error("RootSSH: got false, want true (root over SSH from a dotless host)")
	}
	if info.RemoteCount != 1 {
		t.Errorf("RemoteCount: got %d, want 1", info.RemoteCount)
	}
}

// TestParseSessionsEmptyTTY covers the column-alignment bug found on the real
// VMware tenant: `w -h` prints a BLANK TTY column for a pty-less session (a
// non-interactive `ssh host cmd` / sshd priv-sep entry). strings.Fields collapses
// it, so the FROM IP was read as the TTY and RemoteCount stayed 0 (a false-OK).
func TestParseSessionsEmptyTTY(t *testing.T) {
	t.Parallel()
	// Verbatim `w -h` from the tenant: line 1 has a TTY, line 2 (the SSH command
	// session) has a BLANK TTY column, so FROM/LOGIN@/IDLE/WHAT shift one left.
	out := "" +
		"andrei   tty1     -                Thu22    1:29m  0.09s  0.05s -bash\n" +
		"andrei            79.117.192.102   19:44   13:30m  0.00s  0.03s sshd: andrei [priv]\n"
	info := parseSessions(out)

	if len(info.Sessions) != 2 {
		t.Fatalf("session count: got %d, want 2", len(info.Sessions))
	}
	// Local console line parsed as before.
	if info.Sessions[0].TTY != "tty1" || info.Sessions[0].From != "-" {
		t.Errorf("local line: got TTY=%q From=%q, want tty1 / -", info.Sessions[0].TTY, info.Sessions[0].From)
	}
	// The pty-less SSH line: blank TTY, FROM is the IP — and it counts as remote.
	s := info.Sessions[1]
	if s.TTY != "" {
		t.Errorf("pty-less session TTY: got %q, want empty (blank column)", s.TTY)
	}
	if s.From != "79.117.192.102" {
		t.Errorf("pty-less session From: got %q, want the IP", s.From)
	}
	if s.LoginAt != "19:44" || s.Idle != "13:30m" {
		t.Errorf("pty-less session LOGIN@/IDLE misaligned: got %q / %q", s.LoginAt, s.Idle)
	}
	if s.Command != "sshd: andrei [priv]" {
		t.Errorf("pty-less session WHAT: got %q", s.Command)
	}
	if info.RemoteCount != 1 {
		t.Errorf("RemoteCount: got %d, want 1 (the empty-TTY false-OK)", info.RemoteCount)
	}
}

// TestParseSessionsColumnLayouts pins each `w -h` column shape so the empty-TTY
// fix can't regress the others.
func TestParseSessionsColumnLayouts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                string
		line                string
		wantTTY, wantFrom   string
		wantLogin, wantWhat string
		wantRemote          bool
	}{
		{
			name:    "interactive pts with IP", // TTY + FROM present
			line:    "andrei   pts/0    192.168.1.5      10:00    0.00s  0.01s  0.00s -bash",
			wantTTY: "pts/0", wantFrom: "192.168.1.5", wantLogin: "10:00", wantWhat: "-bash", wantRemote: true,
		},
		{
			name:    "local console blank FROM", // TTY present, FROM column absent
			line:    "root     tty1     -                09:00    55:12  0.02s  0.00s -bash",
			wantTTY: "tty1", wantFrom: "-", wantLogin: "09:00", wantWhat: "-bash", wantRemote: false,
		},
		{
			name:    "X display seat", // ":0" must read as a TTY, not an IPv6 FROM
			line:    "andrei   :0       -                08:00    ?xdm?  1:23   0.00s /usr/lib/gdm",
			wantTTY: ":0", wantFrom: "-", wantLogin: "08:00", wantWhat: "/usr/lib/gdm", wantRemote: false,
		},
		{
			name:    "pty-less SSH blank TTY", // the bug
			line:    "andrei            10.0.0.9         19:44   13:30m  0.00s  0.03s sshd: andrei [priv]",
			wantTTY: "", wantFrom: "10.0.0.9", wantLogin: "19:44", wantWhat: "sshd: andrei [priv]", wantRemote: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := parseSessions(tc.line + "\n")
			if len(info.Sessions) != 1 {
				t.Fatalf("session count: got %d, want 1", len(info.Sessions))
			}
			s := info.Sessions[0]
			if s.TTY != tc.wantTTY {
				t.Errorf("TTY: got %q, want %q", s.TTY, tc.wantTTY)
			}
			if s.From != tc.wantFrom {
				t.Errorf("From: got %q, want %q", s.From, tc.wantFrom)
			}
			if s.LoginAt != tc.wantLogin {
				t.Errorf("LoginAt: got %q, want %q", s.LoginAt, tc.wantLogin)
			}
			if s.Command != tc.wantWhat {
				t.Errorf("Command: got %q, want %q", s.Command, tc.wantWhat)
			}
			if (info.RemoteCount > 0) != tc.wantRemote {
				t.Errorf("remote: got RemoteCount=%d, want remote=%v", info.RemoteCount, tc.wantRemote)
			}
		})
	}
}

// TestParseLVMFloat covers LVM's "<"/">" approximate-size markers, which a plain
// ParseFloat reads as 0 — a false "volume full" signal.
func TestParseLVMFloat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want float64
	}{
		{"19.00", 19.0},
		{"<5.00", 5.0},
		{">5.00", 5.0},
		{"  <0.50 ", 0.5},
		{"", 0},
	}
	for _, tc := range cases {
		if got := parseLVMFloat(tc.in); got != tc.want {
			t.Errorf("parseLVMFloat(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestParseVGsApproxMarker ensures vgs free/size with "<" markers don't read as 0.
func TestParseVGsApproxMarker(t *testing.T) {
	t.Parallel()
	out := "  vg0 <19.00 <5.00 wz--n-\n"
	vgs := parseVGs(out)
	if len(vgs) != 1 {
		t.Fatalf("vg count: got %d, want 1", len(vgs))
	}
	if vgs[0].SizeGB != 19.0 || vgs[0].FreeGB != 5.0 {
		t.Errorf("size/free: got %.2f/%.2f, want 19.00/5.00", vgs[0].SizeGB, vgs[0].FreeGB)
	}
}
