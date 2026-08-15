package cmd

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestPVETaskErrorCritTypes(t *testing.T) {
	t.Parallel()
	errs := []models.PVETaskError{
		{Type: "vzdump"}, {Type: "vzdump"}, {Type: "vzdump"}, // 3 → CRIT
		{Type: "qmigrate"}, {Type: "qmigrate"}, // 2 → not CRIT
		{Type: "vzsnapshot"}, // 1 → not CRIT
	}
	crit := pveTaskErrorCritTypes(errs)
	if !crit["vzdump"] {
		t.Error("vzdump (3 errors) should be CRIT")
	}
	if crit["qmigrate"] {
		t.Error("qmigrate (2 errors) should NOT be CRIT")
	}
	if crit["vzsnapshot"] {
		t.Error("vzsnapshot (1 error) should NOT be CRIT")
	}
	if got := len(pveTaskErrorCritTypes(nil)); got != 0 {
		t.Errorf("nil errors → %d crit types, want 0", got)
	}
}

func TestFormatPVEUptime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sec  int64
		want string
	}{
		{30, "0 minutes"},
		{300, "5 minutes"},
		{3600, "1 hours"},
		{7200, "2 hours"},
		{86400, "1 days"},
		{14 * 86400, "14 days"},
	}
	for _, c := range cases {
		if got := formatPVEUptime(c.sec); got != c.want {
			t.Errorf("formatPVEUptime(%d) = %q, want %q", c.sec, got, c.want)
		}
	}
}

func TestPVEBackupIconAge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		days     int
		wantIcon string
		wantAge  string
	}{
		{-1, iconFail, "never"},
		{0, iconOK, "today"},
		{1, iconOK, "1 day ago"},
		{7, iconOK, "7 days ago"},
		{8, "⚠️ ", "8 days ago"},
		{30, "⚠️ ", "30 days ago"},
		{31, iconFail, "31 days ago"},
		{45, iconFail, "45 days ago"},
	}
	for _, c := range cases {
		icon, age := pveBackupIconAge(c.days, output.ModeHuman)
		if icon != c.wantIcon || age != c.wantAge {
			t.Errorf("pveBackupIconAge(%d) = (%q,%q), want (%q,%q)", c.days, icon, age, c.wantIcon, c.wantAge)
		}
		// In plain mode the icon must be an ASCII token, never an emoji.
		plainIcon, _ := pveBackupIconAge(c.days, output.ModePlain)
		for _, g := range []string{iconFail, "⚠️", iconOK} {
			if plainIcon == g {
				t.Errorf("pveBackupIconAge(%d) plain leaked emoji %q", c.days, g)
			}
		}
	}
}

// TestCountPVEIssuesStorageThreshold guards the `dsd pve` concern tally against
// drifting from the dsd health storage thresholds (analysis.PVEStorageLevel:
// 80 WARN / 90 CRIT). The old hardcoded 85/95 under-counted the 80–84% band, so
// `dsd pve` read "healthy" on a pool dsd health flagged WARN. IsPVE is left false
// so the API-reachable short-circuit doesn't fire and only Storages drives n.
func TestCountPVEIssuesStorageThreshold(t *testing.T) {
	t.Parallel()
	st := func(usedPct float64) *models.PVEInfo {
		return &models.PVEInfo{Storages: []models.PVEStorage{{Name: "local", Active: true, UsedPct: usedPct}}}
	}
	cases := []struct {
		usedPct float64
		want    int
	}{
		{50, 0}, // healthy
		{79, 0}, // just below the health WARN threshold
		{82, 1}, // WARN band the old 85% cutoff missed — must agree with health now
		{90, 1}, // CRIT
	}
	for _, c := range cases {
		if got := countPVEIssues(st(c.usedPct)); got != c.want {
			t.Errorf("countPVEIssues(storage %.0f%%) = %d, want %d (must match analysis.PVEStorageLevel)", c.usedPct, got, c.want)
		}
	}
}

// TestPrintPVEGuests_StripsControlChars guards terminal escape injection: a
// VM/CT name is admin-set inside the guest config but reflected verbatim —
// treat it as untrusted like every other pvesh-sourced string.
func TestPrintPVEGuests_StripsControlChars(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the shared os.Stdout.
	info := &models.PVEInfo{
		RunningCount:   1,
		GuestsVerified: true,
		Guests:         []models.PVEGuest{{VMID: 100, Name: "evil\x1b]0;pwned\x07", Type: "qemu", Status: "running"}},
	}
	out := captureStdout(t, func() { printPVEGuests(info, output.ModePlain) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("printPVEGuests output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printPVEGuests output missing sanitized guest name:\n%s", out)
	}
}

// TestPrintPVEStorage_StripsControlChars guards terminal escape injection on
// the storage pool name.
func TestPrintPVEStorage_StripsControlChars(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the shared os.Stdout.
	info := &models.PVEInfo{Storages: []models.PVEStorage{
		{Name: "evil\x1b]0;pwned\x07", Type: "dir", Active: true, UsedPct: 10},
	}}
	out := captureStdout(t, func() { printPVEStorage(info, output.ModePlain) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("printPVEStorage output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printPVEStorage output missing sanitized storage name:\n%s", out)
	}
}

// TestPrintPVETaskErrors_StripsControlChars guards terminal escape injection
// on task-error fields (Type/VMID/StartAt/Msg all come from pvesh task logs).
func TestPrintPVETaskErrors_StripsControlChars(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the shared os.Stdout.
	info := &models.PVEInfo{TaskErrors: []models.PVETaskError{
		{Type: "vzdump", VMID: "100", StartAt: "10:00", Msg: "evil\x1b]0;pwned\x07"},
	}}
	out := captureStdout(t, func() { printPVETaskErrors(info, output.ModePlain) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("printPVETaskErrors output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printPVETaskErrors output missing sanitized message:\n%s", out)
	}
}

// TestPrintPVETaskErrors_RuneSafeTruncation covers cmd-11-05: the old
// msg[:77] byte-offset truncation could split a multi-byte UTF-8 rune
// straddling the cut point, writing invalid UTF-8 to stdout. Build a message
// with a 3-byte rune positioned right at the byte-77 boundary and assert the
// rendered output stays valid UTF-8.
func TestPrintPVETaskErrors_RuneSafeTruncation(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the shared os.Stdout.
	// 76 ASCII runes (bytes 0-75) + one 3-byte rune (bytes 76-78, i.e.
	// straddling byte offset 77) + a long ASCII tail to push well past the cap.
	msg := strings.Repeat("a", 76) + "世" + strings.Repeat("b", 40)
	info := &models.PVEInfo{TaskErrors: []models.PVETaskError{
		{Type: "vzdump", VMID: "100", StartAt: "10:00", Msg: msg},
	}}
	out := captureStdout(t, func() { printPVETaskErrors(info, output.ModePlain) })
	if !utf8.ValidString(out) {
		t.Errorf("printPVETaskErrors output is not valid UTF-8 after truncation:\n%q", out)
	}
	if !strings.Contains(out, "世") {
		t.Errorf("expected the boundary rune to survive truncation intact, got:\n%s", out)
	}
}

// TestPrintPVECluster_StripsControlChars guards terminal escape injection on
// the cluster name and per-node names.
func TestPrintPVECluster_StripsControlChars(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the shared os.Stdout.
	info := &models.PVEInfo{
		ClusterName: "evil\x1b]0;pwned\x07",
		QuorumOK:    true,
		Nodes:       []models.PVENode{{Name: "node\x1b]0;pwned\x07", Online: true}},
	}
	out := captureStdout(t, func() { printPVECluster(info, output.ModePlain) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("printPVECluster output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") || !strings.Contains(out, "node]0;pwned") {
		t.Errorf("printPVECluster output missing sanitized names:\n%s", out)
	}
}

// TestPrintPVEBridges_StripsControlChars guards terminal escape injection on
// bridge name and bridge_ports fields.
func TestPrintPVEBridges_StripsControlChars(t *testing.T) {
	// No t.Parallel(): captureStdout swaps the shared os.Stdout.
	info := &models.PVEInfo{Bridges: []models.PVEBridge{
		{Name: "evil\x1b]0;pwned\x07", Active: true, HasUplink: true, Ports: "eth\x1b[2J0", STPEnabled: true},
	}}
	out := captureStdout(t, func() { printPVEBridges(info, output.ModePlain) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("printPVEBridges output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printPVEBridges output missing sanitized bridge name:\n%s", out)
	}
	if !strings.Contains(out, "eth[2J0") {
		t.Errorf("printPVEBridges output missing sanitized ports field:\n%s", out)
	}
}
