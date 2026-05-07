package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault_Values(t *testing.T) {
	cfg := Default()

	checks := []struct {
		name string
		got  float64
		want float64
	}{
		{"DiskWarnPct", cfg.Thresholds.DiskWarnPct, 80.0},
		{"DiskCritPct", cfg.Thresholds.DiskCritPct, 90.0},
		{"RAMWarnPct", cfg.Thresholds.RAMWarnPct, 80.0},
		{"RAMCritPct", cfg.Thresholds.RAMCritPct, 95.0},
		{"CPULoadWarnMultiplier", cfg.Thresholds.CPULoadWarnMultiplier, 0.7},
		{"CPULoadCritMultiplier", cfg.Thresholds.CPULoadCritMultiplier, 0.9},
		{"IOUtilWarnPct", cfg.Thresholds.IOUtilWarnPct, 60.0},
		{"IOUtilCritPct", cfg.Thresholds.IOUtilCritPct, 85.0},
		{"IOAwaitWarnMs", cfg.Thresholds.IOAwaitWarnMs, 2.0},
		{"IOAwaitCritMs", cfg.Thresholds.IOAwaitCritMs, 10.0},
		{"SwapWarnPct", cfg.Thresholds.SwapWarnPct, 20.0},
		{"SwapCritPct", cfg.Thresholds.SwapCritPct, 60.0},
		{"NTPWarnMs", cfg.Thresholds.NTPWarnMs, 100.0},
		{"NTPCritMs", cfg.Thresholds.NTPCritMs, 500.0},
		{"FDWarnPct", cfg.Thresholds.FDWarnPct, 80.0},
		{"FDCritPct", cfg.Thresholds.FDCritPct, 90.0},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}

	if cfg.Logs.SinceMinutes != 60 {
		t.Errorf("SinceMinutes: got %d, want 60", cfg.Logs.SinceMinutes)
	}
	if cfg.Security.SSHFailedLoginWarn != 20 {
		t.Errorf("SSHFailedLoginWarn: got %d, want 20", cfg.Security.SSHFailedLoginWarn)
	}
	if cfg.Security.SSHFailedLoginCrit != 50 {
		t.Errorf("SSHFailedLoginCrit: got %d, want 50", cfg.Security.SSHFailedLoginCrit)
	}

	wantPorts := []int{22, 80, 443, 8080, 8443, 5432, 3306, 6379}
	if len(cfg.Security.AllowedPorts) != len(wantPorts) {
		t.Errorf("AllowedPorts len: got %d, want %d", len(cfg.Security.AllowedPorts), len(wantPorts))
	} else {
		for i, p := range wantPorts {
			if cfg.Security.AllowedPorts[i] != p {
				t.Errorf("AllowedPorts[%d]: got %d, want %d", i, cfg.Security.AllowedPorts[i], p)
			}
		}
	}
}

func TestDefault_IsACopy(t *testing.T) {
	a := Default()
	b := Default()
	a.Thresholds.DiskWarnPct = 99
	if b.Thresholds.DiskWarnPct == 99 {
		t.Error("Default() must return independent copies — mutation leaked")
	}
}

func TestLoad_NoFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with no file: %v", err)
	}
	if cfg.Thresholds.DiskWarnPct != 80.0 {
		t.Errorf("expected default DiskWarnPct=80, got %v", cfg.Thresholds.DiskWarnPct)
	}
	if cfg.Logs.SinceMinutes != 60 {
		t.Errorf("expected default SinceMinutes=60, got %d", cfg.Logs.SinceMinutes)
	}
}

func TestLoad_CustomFile_FullOverride(t *testing.T) {
	dir := t.TempDir()
	yaml := `
thresholds:
  disk_warn_pct: 70
  disk_crit_pct: 85
  ram_warn_pct: 75
  ram_crit_pct: 92
  ntp_warn_ms: 50
  ntp_crit_ms: 200
logs:
  since_minutes: 120
security:
  ssh_failed_login_warn: 10
  ssh_failed_login_crit: 30
`
	cfgFile := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(cfgFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Thresholds.DiskWarnPct != 70 {
		t.Errorf("DiskWarnPct: got %v, want 70", cfg.Thresholds.DiskWarnPct)
	}
	if cfg.Thresholds.DiskCritPct != 85 {
		t.Errorf("DiskCritPct: got %v, want 85", cfg.Thresholds.DiskCritPct)
	}
	if cfg.Thresholds.RAMWarnPct != 75 {
		t.Errorf("RAMWarnPct: got %v, want 75", cfg.Thresholds.RAMWarnPct)
	}
	if cfg.Thresholds.NTPWarnMs != 50 {
		t.Errorf("NTPWarnMs: got %v, want 50", cfg.Thresholds.NTPWarnMs)
	}
	if cfg.Logs.SinceMinutes != 120 {
		t.Errorf("SinceMinutes: got %d, want 120", cfg.Logs.SinceMinutes)
	}
	if cfg.Security.SSHFailedLoginWarn != 10 {
		t.Errorf("SSHFailedLoginWarn: got %d, want 10", cfg.Security.SSHFailedLoginWarn)
	}
}

func TestLoad_PartialOverride(t *testing.T) {
	dir := t.TempDir()
	yaml := `
thresholds:
  disk_warn_pct: 65
`
	cfgFile := filepath.Join(dir, "partial.yaml")
	_ = os.WriteFile(cfgFile, []byte(yaml), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Overridden value
	if cfg.Thresholds.DiskWarnPct != 65 {
		t.Errorf("DiskWarnPct: got %v, want 65", cfg.Thresholds.DiskWarnPct)
	}
	// Unspecified values must come from defaults
	if cfg.Thresholds.DiskCritPct != 90.0 {
		t.Errorf("DiskCritPct should be default 90, got %v", cfg.Thresholds.DiskCritPct)
	}
	if cfg.Thresholds.RAMWarnPct != 80.0 {
		t.Errorf("RAMWarnPct should be default 80, got %v", cfg.Thresholds.RAMWarnPct)
	}
	if cfg.Logs.SinceMinutes != 60 {
		t.Errorf("SinceMinutes should be default 60, got %d", cfg.Logs.SinceMinutes)
	}
}

func TestLoad_WithServices(t *testing.T) {
	dir := t.TempDir()
	yaml := `
services:
  - name: postgres
    host: localhost
    port: 5432
    protocol: tcp
  - name: redis
    host: 127.0.0.1
    port: 6379
    protocol: tcp
`
	cfgFile := filepath.Join(dir, "services.yaml")
	_ = os.WriteFile(cfgFile, []byte(yaml), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(cfg.Services))
	}
	if cfg.Services[0].Name != "postgres" || cfg.Services[0].Port != 5432 {
		t.Errorf("services[0]: got %+v", cfg.Services[0])
	}
	if cfg.Services[1].Name != "redis" || cfg.Services[1].Port != 6379 {
		t.Errorf("services[1]: got %+v", cfg.Services[1])
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(cfgFile, []byte("thresholds: [not: valid: yaml: {{\n"), 0644)

	// Load should not panic — it may return error or fall back to defaults
	cfg, err := Load(cfgFile)
	if err != nil {
		// error is acceptable
		return
	}
	// if no error, must have valid threshold values
	if cfg.Thresholds.DiskWarnPct <= 0 {
		t.Error("expected positive DiskWarnPct even on parse error")
	}
}
