package config

import (
	"os"
	"path/filepath"
	"strings"
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

// TestLoad_HomeDirUnresolvable guards internal-config-01-04: when
// os.UserHomeDir() fails (stripped/empty $HOME — cron/systemd/container
// invocation), Load must not silently fall back to a CWD-relative
// ".dsd.yaml" (which could pick up an attacker-writable file from whatever
// directory dsd happens to run from). It must return defaults plus a
// disclosed error instead.
func TestLoad_HomeDirUnresolvable(t *testing.T) {
	t.Setenv("HOME", "") // os.UserHomeDir() on Unix errors when $HOME is empty

	cfg, err := Load("")
	if err == nil {
		t.Fatal("Load() with unresolvable $HOME = nil error, want a disclosed error")
	}
	if cfg == nil {
		t.Fatal("Load() with unresolvable $HOME = nil config, want defaults")
	}
	if cfg.Thresholds.DiskWarnPct != defaults.Thresholds.DiskWarnPct {
		t.Errorf("expected defaults on unresolvable $HOME, got %+v", cfg.Thresholds)
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

// TestLoad_RootSkipsNonRootOwnedImplicitConfig is a regression guard: a root
// process must not silently trust an auto-discovered $HOME/.dsd.yaml when
// that file is owned by someone other than root (e.g. `sudo -E dsd` preserved
// an unprivileged user's $HOME). Its Services list drives real outbound TCP
// dials from internal/collectors/services.go — trusting it would let the
// unprivileged file owner steer a privileged process's network connections.
func TestLoad_RootSkipsNonRootOwnedImplicitConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfgPath := filepath.Join(dir, ".dsd.yaml")
	yaml := `
services:
  - name: attacker-controlled
    host: 10.0.0.1
    port: 4444
    protocol: tcp
thresholds:
  disk_warn_pct: 1
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevEuid, prevOwner := geteuid, fileOwner
	geteuid = func() int { return 0 }                          // simulate root
	fileOwner = func(string) (int, bool) { return 1000, true } // owned by a non-root uid
	defer func() { geteuid, fileOwner = prevEuid, prevOwner }()

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("root process must not trust a non-root-owned implicit $HOME config; got Services=%+v", cfg.Services)
	}
	if cfg.Thresholds.DiskWarnPct != 80.0 {
		t.Errorf("expected default DiskWarnPct=80 (config skipped), got %v", cfg.Thresholds.DiskWarnPct)
	}
}

// TestLoad_RootTrustsRootOwnedImplicitConfig confirms the ownership gate only
// blocks non-root-owned files: a root-owned $HOME config (the normal case
// when dsd itself always runs as root on a box) must still be honored.
func TestLoad_RootTrustsRootOwnedImplicitConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfgPath := filepath.Join(dir, ".dsd.yaml")
	yaml := `
services:
  - name: postgres
    host: localhost
    port: 5432
    protocol: tcp
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevEuid, prevOwner := geteuid, fileOwner
	geteuid = func() int { return 0 }                       // simulate root
	fileOwner = func(string) (int, bool) { return 0, true } // owned by root
	defer func() { geteuid, fileOwner = prevEuid, prevOwner }()

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Name != "postgres" {
		t.Fatalf("root process should trust its own root-owned implicit config, got Services=%+v", cfg.Services)
	}
}

// TestLoad_ExplicitConfigBypassesOwnershipCheck confirms an explicit --config
// path (a deliberate operator choice) is never subject to the implicit-$HOME
// ownership gate, even while running as root.
func TestLoad_ExplicitConfigBypassesOwnershipCheck(t *testing.T) {
	dir := t.TempDir()
	yaml := `
services:
  - name: postgres
    host: localhost
    port: 5432
    protocol: tcp
`
	cfgFile := filepath.Join(dir, "explicit.yaml")
	if err := os.WriteFile(cfgFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevEuid, prevOwner := geteuid, fileOwner
	geteuid = func() int { return 0 }                          // simulate root
	fileOwner = func(string) (int, bool) { return 1000, true } // non-root owner
	defer func() { geteuid, fileOwner = prevEuid, prevOwner }()

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Name != "postgres" {
		t.Fatalf("explicit --config path must bypass the ownership gate, got Services=%+v", cfg.Services)
	}
}

// TestLoad_ImplicitConfigSymlinkRefused confirms an implicit $HOME config
// that is a symlink is refused outright, regardless of what it points at or
// the process's privilege level — closing the gap where only root had any
// check at all (ownership), and even that used Stat (follows symlinks).
func TestLoad_ImplicitConfigSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	target := filepath.Join(dir, "real-target.yaml")
	yaml := `
services:
  - name: attacker-controlled
    host: 10.0.0.1
    port: 4444
    protocol: tcp
`
	if err := os.WriteFile(target, []byte(yaml), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	cfgPath := filepath.Join(dir, ".dsd.yaml")
	if err := os.Symlink(target, cfgPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("a symlinked implicit config must be refused, got Services=%+v", cfg.Services)
	}
}

// TestLoad_ImplicitConfigWorldWritableRefused confirms a group/world-writable
// implicit $HOME config is refused: its content isn't exclusively controlled
// by its apparent owner, so ownership alone (the existing root-only check)
// isn't sufficient trust evidence.
func TestLoad_ImplicitConfigWorldWritableRefused(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfgPath := filepath.Join(dir, ".dsd.yaml")
	yaml := `
services:
  - name: attacker-controlled
    host: 10.0.0.1
    port: 4444
    protocol: tcp
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0666); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// os.WriteFile's mode is masked by the process umask (typically 022),
	// which would silently strip the group/world write bits this test needs
	// to exercise — os.Chmod bypasses the umask and sets the mode exactly.
	if err := os.Chmod(cfgPath, 0666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("a world-writable implicit config must be refused, got Services=%+v", cfg.Services)
	}
}

// TestLoad_ImplicitConfigOversizeRefused confirms an implicit $HOME config
// over the size cap is refused with a disclosed error, before ever reaching
// viper's unbounded read.
func TestLoad_ImplicitConfigOversizeRefused(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfgPath := filepath.Join(dir, ".dsd.yaml")

	f, err := os.OpenFile(cfgPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(maxImplicitConfigBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	cfg, err := Load("")
	if err == nil {
		t.Fatal("expected an error for an oversized implicit config")
	}
	if len(cfg.Services) != 0 || cfg.Thresholds.DiskWarnPct != 80.0 {
		t.Fatalf("oversized implicit config must fall back to defaults, got %+v", cfg)
	}
}

// TestLoad_ExplicitConfigBypassesSymlinkAndWritableChecks confirms an
// explicit --config path (a deliberate operator choice) is never subject to
// the new implicit-$HOME symlink/writable-bits/size checks, mirroring the
// existing explicit-bypasses-ownership-check guarantee above.
func TestLoad_ExplicitConfigBypassesSymlinkAndWritableChecks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-target.yaml")
	yaml := `
services:
  - name: postgres
    host: localhost
    port: 5432
    protocol: tcp
`
	if err := os.WriteFile(target, []byte(yaml), 0666); err != nil {
		t.Fatalf("write target: %v", err)
	}
	cfgFile := filepath.Join(dir, "explicit.yaml")
	if err := os.Symlink(target, cfgFile); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Name != "postgres" {
		t.Fatalf("explicit --config path must bypass the new implicit-path checks, got Services=%+v", cfg.Services)
	}
}

// TestImplicitConfigSafe exercises the real (non-mocked) implicit-config
// trust check directly, matching TestDefaultFileOwner's style below.
func TestImplicitConfigSafe(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "missing.yaml")
	if safe, err := implicitConfigSafe(missing); !safe || err != nil {
		t.Errorf("missing file: got safe=%v err=%v, want safe=true err=nil", safe, err)
	}

	regular := filepath.Join(dir, "regular.yaml")
	if err := os.WriteFile(regular, []byte("x"), 0600); err != nil {
		t.Fatalf("write regular: %v", err)
	}
	if safe, err := implicitConfigSafe(regular); !safe || err != nil {
		t.Errorf("regular 0600 file: got safe=%v err=%v, want safe=true err=nil", safe, err)
	}

	writable := filepath.Join(dir, "writable.yaml")
	if err := os.WriteFile(writable, []byte("x"), 0664); err != nil {
		t.Fatalf("write writable: %v", err)
	}
	// os.Chmod bypasses the umask (see the analogous comment in
	// TestLoad_ImplicitConfigWorldWritableRefused) so the group-write bit
	// this test needs actually lands.
	if err := os.Chmod(writable, 0664); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if safe, _ := implicitConfigSafe(writable); safe {
		t.Error("group-writable file: want safe=false")
	}

	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if safe, _ := implicitConfigSafe(link); safe {
		t.Error("symlink: want safe=false")
	}
}

// TestDefaultFileOwner exercises the real (non-mocked) ownership resolver.
func TestDefaultFileOwner(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "owned.yaml")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	uid, ok := defaultFileOwner(f)
	if !ok {
		t.Fatal("expected ok=true for an existing file")
	}
	if uid != os.Getuid() {
		t.Errorf("uid = %d, want the real process uid %d", uid, os.Getuid())
	}

	if _, ok := defaultFileOwner(filepath.Join(dir, "missing.yaml")); ok {
		t.Error("expected ok=false for a missing file")
	}
}

// TestLoad_UnmarshalTypeMismatch covers the v.Unmarshal error path
// specifically: this is syntactically valid YAML (ReadInConfig succeeds) but
// a field's shape doesn't coerce into the target Go struct (a mapping where a
// float64 scalar is expected), so mapstructure decoding fails. This is
// distinct from TestLoad_InvalidYAML, which is malformed YAML syntax that
// fails earlier, at ReadInConfig, never reaching Unmarshal at all — both
// paths now return a non-nil error (internal-config-01-01), just from a
// different stage of parsing.
func TestLoad_UnmarshalTypeMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	yaml := `
thresholds:
  disk_warn_pct:
    nested: not-a-number
`
	cfgFile := filepath.Join(dir, "typemismatch.yaml")
	if err := os.WriteFile(cfgFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected an error decoding a mapping into a float64 field, got nil")
	}
	if !strings.Contains(err.Error(), "parsing config") {
		t.Errorf("expected 'parsing config' wrapped error, got %v", err)
	}
}

// TestLoad_RejectsInvalidValues guards Finding internal-config-01-03: after
// v.Unmarshal populates Config, no field was validated — a YAML special
// float (.nan, .inf), a negative threshold/count, or an out-of-range
// Services port/empty host would pass through Load() unchecked and reach
// whatever downstream code trusts these fields as pre-validated.
func TestLoad_RejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"NaN threshold", "thresholds:\n  disk_warn_pct: .nan\n"},
		{"Inf threshold", "thresholds:\n  disk_crit_pct: .inf\n"},
		{"negative threshold", "thresholds:\n  ram_warn_pct: -5\n"},
		{"negative ssh_failed_login_warn", "security:\n  ssh_failed_login_warn: -1\n"},
		{"negative ssh_failed_login_crit", "security:\n  ssh_failed_login_crit: -1\n"},
		{"out-of-range allowed_ports", "security:\n  allowed_ports: [70000]\n"},
		{"allowed_ports zero", "security:\n  allowed_ports: [0]\n"},
		{"service missing name", "services:\n  - host: localhost\n    port: 5432\n"},
		{"service missing host", "services:\n  - name: postgres\n    port: 5432\n"},
		{"service port zero", "services:\n  - name: postgres\n    host: localhost\n    port: 0\n"},
		{"service port out of range", "services:\n  - name: postgres\n    host: localhost\n    port: 70000\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgFile := filepath.Join(dir, "invalid.yaml")
			if err := os.WriteFile(cfgFile, []byte(c.yaml), 0644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(cfgFile)
			if err == nil {
				t.Fatalf("Load(%q) = nil error, want a validation error", c.yaml)
			}
			if !strings.Contains(err.Error(), "invalid config") {
				t.Errorf("expected 'invalid config' wrapped error, got %v", err)
			}
		})
	}
}

// TestLoad_ValidConfigStillLoads guards against Validate() being overly
// strict: a well-formed config (matching TestLoad_WithServices' shape) must
// still load without error.
func TestLoad_ValidConfigStillLoads(t *testing.T) {
	dir := t.TempDir()
	yaml := `
thresholds:
  disk_warn_pct: 70
security:
  ssh_failed_login_warn: 10
  ssh_failed_login_crit: 30
  allowed_ports: [22, 443]
services:
  - name: postgres
    host: localhost
    port: 5432
    protocol: tcp
`
	cfgFile := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(cfgFile, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgFile); err != nil {
		t.Errorf("Load(valid config) = %v, want nil", err)
	}
}

// TestConfigValidate_ThresholdBoundaries is a direct table-driven boundary
// test of ThresholdConfig.validate: exactly 0 is accepted (the floor), just
// below it is rejected.
func TestConfigValidate_ThresholdBoundaries(t *testing.T) {
	t.Parallel()
	valid := defaults
	if err := valid.Validate(); err != nil {
		t.Fatalf("defaults must validate cleanly: %v", err)
	}

	atFloor := defaults
	atFloor.Thresholds.DiskWarnPct = 0
	if err := atFloor.Validate(); err != nil {
		t.Errorf("DiskWarnPct=0 (the floor) must be accepted: %v", err)
	}

	belowFloor := defaults
	belowFloor.Thresholds.DiskWarnPct = -0.001
	if err := belowFloor.Validate(); err == nil {
		t.Error("DiskWarnPct=-0.001 (just below the floor) must be rejected")
	}
}

// TestConfigValidate_ServicePortBoundaries is a direct table-driven boundary
// test of ServiceConfig.validate: 1 and 65535 are accepted, 0 and 65536 are
// rejected.
func TestConfigValidate_ServicePortBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		port    int
		wantErr bool
	}{
		{0, true},
		{1, false},
		{65535, false},
		{65536, true},
	}
	for _, c := range cases {
		cfg := defaults
		cfg.Services = []ServiceConfig{{Name: "svc", Host: "localhost", Port: c.port, Protocol: "tcp"}}
		err := cfg.Validate()
		if (err != nil) != c.wantErr {
			t.Errorf("port=%d: err=%v, wantErr=%v", c.port, err, c.wantErr)
		}
	}
}

// TestConfigValidate_ServiceProtocol guards internal-config-01-03: Protocol
// previously had no validation at all, so a typo (or an unsupported value
// like "udp") silently fell into services.go's checkServiceLive `default: //
// tcp` branch and got probed as if it were TCP. Only the values the collector
// actually understands ("tcp", "http", "https") must validate.
func TestConfigValidate_ServiceProtocol(t *testing.T) {
	t.Parallel()
	cases := []struct {
		protocol string
		wantErr  bool
	}{
		{"tcp", false},
		{"http", false},
		{"https", false},
		{"", true},
		{"udp", true},
		{"HTTP", true}, // case-sensitive: must match the collector's switch exactly
	}
	for _, c := range cases {
		cfg := defaults
		cfg.Services = []ServiceConfig{{Name: "svc", Host: "localhost", Port: 80, Protocol: c.protocol}}
		err := cfg.Validate()
		if (err != nil) != c.wantErr {
			t.Errorf("protocol=%q: err=%v, wantErr=%v", c.protocol, err, c.wantErr)
		}
	}
}

// TestLoad_InvalidYAML guards internal-config-01-01: a config file that
// EXISTS but fails to parse must return a non-nil error (surfaced by the
// caller, e.g. ServicesCollector, as a disclosed INFO) rather than silently
// falling back to defaults with a nil error — indistinguishable from the
// user never having written a config file at all. Defaults are still
// returned alongside the error so a caller that only needs to keep running
// can do so.
func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(cfgFile, []byte("thresholds: [not: valid: yaml: {{\n"), 0644)

	cfg, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected a non-nil error for a config file that exists but fails to parse")
	}
	// Defaults must still be usable even though the error is non-nil.
	if cfg == nil || cfg.Thresholds.DiskWarnPct <= 0 {
		t.Error("expected valid default threshold values alongside the error")
	}
}

// TestLoad_MissingExplicitFile_NoError guards the OTHER half of
// internal-config-01-01: an explicitly-named config file that simply doesn't
// exist is the documented "no config" case and must stay silent (defaults,
// nil error) — only a file that exists but can't be read/parsed should
// surface an error.
func TestLoad_MissingExplicitFile_NoError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "does-not-exist.yaml")

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load with a missing (never-created) config file should not error, got: %v", err)
	}
	if cfg.Thresholds.DiskWarnPct != 80.0 {
		t.Errorf("expected default DiskWarnPct=80, got %v", cfg.Thresholds.DiskWarnPct)
	}
}
