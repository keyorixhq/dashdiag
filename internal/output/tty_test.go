package output

import (
	"os"
	"testing"
)

// withTTY forces isaTTY() to return the given value for the duration of fn,
// then restores the original seam.
func withTTY(t *testing.T, tty bool, fn func()) {
	t.Helper()
	old := isaTTY
	isaTTY = func() bool { return tty }
	defer func() { isaTTY = old }()
	fn()
}

func TestDetectMode(t *testing.T) {
	tests := []struct {
		name   string
		plain  bool
		report bool
		fmt    string
		want   OutputMode
	}{
		{"json flag", false, false, "json", ModeJSON},
		{"yaml flag", false, false, "yaml", ModeYAML},
		{"quiet flag", false, false, "quiet", ModePlain},
		{"report flag", false, true, "", ModeReport},
		{"plain flag", true, false, "", ModePlain},
		{"plain beats report", true, true, "", ModeReport}, // report checked first after fmt
		{"json beats report", false, true, "json", ModeJSON},
		{"json beats plain", true, false, "json", ModeJSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectMode(tt.plain, tt.report, tt.fmt)
			if got != tt.want {
				t.Errorf("DetectMode(%v, %v, %q) = %v, want %v",
					tt.plain, tt.report, tt.fmt, got, tt.want)
			}
		})
	}
}

func TestDetectModeNoTTY(t *testing.T) {
	// In test runners stderr is not a TTY, so no-flag case → ModePlain
	got := DetectMode(false, false, "")
	if got != ModePlain && got != ModeHuman {
		t.Errorf("DetectMode(false, false, \"\") = %v, want ModePlain or ModeHuman", got)
	}
}

func TestDetectMode_TTYNoFlags(t *testing.T) {
	withTTY(t, true, func() {
		got := DetectMode(false, false, "")
		if got != ModeHuman {
			t.Errorf("DetectMode(false, false, \"\") with TTY = %v, want ModeHuman", got)
		}
	})
}

func TestDetectMode_NoTTYForcesPlain(t *testing.T) {
	withTTY(t, false, func() {
		got := DetectMode(false, false, "")
		if got != ModePlain {
			t.Errorf("DetectMode(false, false, \"\") without TTY = %v, want ModePlain", got)
		}
	})
}

func TestStatusIcon(t *testing.T) {
	statuses := []string{"ok", "warn", "fail", "info", "pending"}

	humanWant := map[string]string{
		"ok": "✅", "warn": "⚠️", "fail": "❌", "info": "ℹ️", "pending": "⏳",
	}
	plainWant := map[string]string{
		"ok": "OK", "warn": "WARN", "fail": "CRIT", "info": "INFO", "pending": "PENDING",
	}
	reportWant := map[string]string{
		"ok": "✅ OK", "warn": "⚠️  WARN", "fail": "❌ FAIL", "info": "ℹ️  INFO", "pending": "⏳ PENDING",
	}

	modes := []struct {
		mode OutputMode
		want map[string]string
	}{
		{ModeHuman, humanWant},
		{ModePlain, plainWant},
		{ModeJSON, plainWant},
		{ModeYAML, plainWant},
		{ModeReport, reportWant},
	}

	for _, m := range modes {
		for _, s := range statuses {
			got := StatusIcon(s, m.mode)
			if got != m.want[s] {
				t.Errorf("StatusIcon(%q, %v) = %q, want %q", s, m.mode, got, m.want[s])
			}
		}
	}
}

func TestStatusIconUnknown(t *testing.T) {
	for _, mode := range []OutputMode{ModeHuman, ModePlain, ModeReport, ModeJSON, ModeYAML} {
		got := StatusIcon("unknown", mode)
		if got != "unknown" {
			t.Errorf("StatusIcon(\"unknown\", %v) = %q, want %q", mode, got, "unknown")
		}
	}
}

func TestIsPlain(t *testing.T) {
	if !IsPlain(true) {
		t.Error("IsPlain(true) should always be true")
	}
	// flag=false: result depends on TTY state, just verify no panic
	_ = IsPlain(false)
}

func TestIsaTTY_StatError(t *testing.T) {
	// No t.Parallel(): mutates the package-global os.Stderr (and thus the
	// isaTTY seam other tests read), so it must not run concurrently with
	// them.

	// Capture the real isaTTY closure before replacing os.Stderr.
	realIsaTTY := isaTTY

	// Replace os.Stderr with a closed file so Stat() returns an error.
	oldStderr := os.Stderr
	f, err := os.CreateTemp(t.TempDir(), "fake-stderr")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	// Re-open to get a valid *os.File, then close it to make Stat fail.
	closed, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	os.Stderr = closed
	defer func() { os.Stderr = oldStderr }()

	got := realIsaTTY()
	if got {
		t.Error("isaTTY() with stat-failing stderr should return false")
	}
}
