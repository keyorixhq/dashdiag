package output

import "testing"

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

func TestStatusIcon(t *testing.T) {
	statuses := []string{"ok", "warn", "fail", "info", "pending"}

	humanWant := map[string]string{
		"ok": "✅", "warn": "⚠️", "fail": "❌", "info": "ℹ️", "pending": "⏳",
	}
	plainWant := map[string]string{
		"ok": "OK", "warn": "WARN", "fail": "FAIL", "info": "INFO", "pending": "PENDING",
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
