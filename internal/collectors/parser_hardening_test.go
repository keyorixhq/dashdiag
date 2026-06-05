package collectors

import "testing"

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
		// LOGIN@ timestamps (no FROM column)
		{"-", false},
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
