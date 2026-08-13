package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/viper"
)

type Config struct {
	Thresholds ThresholdConfig `yaml:"thresholds" mapstructure:"thresholds"`
	Logs       LogsConfig      `yaml:"logs"       mapstructure:"logs"`
	Security   SecurityConfig  `yaml:"security"   mapstructure:"security"`
	Services   []ServiceConfig `yaml:"services"   mapstructure:"services"`
}

type ThresholdConfig struct {
	DiskWarnPct           float64 `yaml:"disk_warn_pct"            mapstructure:"disk_warn_pct"`
	DiskCritPct           float64 `yaml:"disk_crit_pct"            mapstructure:"disk_crit_pct"`
	RAMWarnPct            float64 `yaml:"ram_warn_pct"             mapstructure:"ram_warn_pct"`
	RAMCritPct            float64 `yaml:"ram_crit_pct"             mapstructure:"ram_crit_pct"`
	CPULoadWarnMultiplier float64 `yaml:"cpu_load_warn_multiplier" mapstructure:"cpu_load_warn_multiplier"`
	CPULoadCritMultiplier float64 `yaml:"cpu_load_crit_multiplier" mapstructure:"cpu_load_crit_multiplier"`
	IOUtilWarnPct         float64 `yaml:"io_util_warn_pct"         mapstructure:"io_util_warn_pct"`
	IOUtilCritPct         float64 `yaml:"io_util_crit_pct"         mapstructure:"io_util_crit_pct"`
	IOAwaitWarnMs         float64 `yaml:"io_await_warn_ms"         mapstructure:"io_await_warn_ms"`
	IOAwaitCritMs         float64 `yaml:"io_await_crit_ms"         mapstructure:"io_await_crit_ms"`
	SwapWarnPct           float64 `yaml:"swap_warn_pct"            mapstructure:"swap_warn_pct"`
	SwapCritPct           float64 `yaml:"swap_crit_pct"            mapstructure:"swap_crit_pct"`
	NTPWarnMs             float64 `yaml:"ntp_warn_ms"              mapstructure:"ntp_warn_ms"`
	NTPCritMs             float64 `yaml:"ntp_crit_ms"              mapstructure:"ntp_crit_ms"`
	FDWarnPct             float64 `yaml:"fd_warn_pct"              mapstructure:"fd_warn_pct"`
	FDCritPct             float64 `yaml:"fd_crit_pct"              mapstructure:"fd_crit_pct"`
}

type LogsConfig struct {
	SinceMinutes int `yaml:"since_minutes" mapstructure:"since_minutes"`
}

type SecurityConfig struct {
	AllowedPorts       []int `yaml:"allowed_ports"         mapstructure:"allowed_ports"`
	SSHFailedLoginWarn int   `yaml:"ssh_failed_login_warn" mapstructure:"ssh_failed_login_warn"`
	SSHFailedLoginCrit int   `yaml:"ssh_failed_login_crit" mapstructure:"ssh_failed_login_crit"`
}

type ServiceConfig struct {
	Name     string `yaml:"name"     mapstructure:"name"`
	Host     string `yaml:"host"     mapstructure:"host"`
	Port     int    `yaml:"port"     mapstructure:"port"`
	Protocol string `yaml:"protocol" mapstructure:"protocol"`
}

var defaults = Config{
	Thresholds: ThresholdConfig{
		DiskWarnPct:           80.0,
		DiskCritPct:           90.0,
		RAMWarnPct:            80.0,
		RAMCritPct:            95.0,
		CPULoadWarnMultiplier: 0.7,
		CPULoadCritMultiplier: 0.9,
		IOUtilWarnPct:         60.0,
		IOUtilCritPct:         85.0,
		IOAwaitWarnMs:         2.0,
		IOAwaitCritMs:         10.0,
		SwapWarnPct:           20.0,
		SwapCritPct:           60.0,
		NTPWarnMs:             100.0,
		NTPCritMs:             500.0,
		FDWarnPct:             80.0,
		FDCritPct:             90.0,
	},
	Logs: LogsConfig{SinceMinutes: 60},
	Security: SecurityConfig{
		AllowedPorts:       []int{22, 80, 443, 8080, 8443, 5432, 3306, 6379},
		SSHFailedLoginWarn: 20,
		SSHFailedLoginCrit: 50,
	},
}

// geteuid and fileOwner are seams so tests can exercise the root and
// non-root ownership-check branches below deterministically, regardless of
// the uid the test binary actually runs under (same seam pattern used by
// internal/collectors' geteuid — see collector.go).
var geteuid = os.Geteuid

// fileOwner reports the resolved owner uid of path. Returns ok=false when the
// file doesn't exist or ownership can't be determined on this platform.
var fileOwner = defaultFileOwner

func defaultFileOwner(path string) (uid int, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, statOK := fi.Sys().(*syscall.Stat_t)
	if !statOK {
		return 0, false
	}
	return int(st.Uid), true
}

func Load(cfgFile string) (*Config, error) {
	v := viper.New()
	implicitPath := cfgFile == ""
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, _ := os.UserHomeDir()
		cfgFile = filepath.Join(home, ".dsd.yaml")
		v.SetConfigFile(cfgFile)
	}

	// A root process must not silently trust an auto-discovered $HOME config it
	// never explicitly asked for (no --config flag) when that file is owned by
	// someone other than root. `sudo -E dsd`, `su -m`, or a stale service/cron
	// $HOME can preserve an unprivileged user's $HOME into a privileged dsd
	// process, and cfg.Services drives real outbound TCP/HTTP dials from
	// internal/collectors/services.go — an attacker who controls that file
	// would otherwise steer a privileged process's network connections. An
	// explicit --config path is a deliberate operator choice and is trusted as
	// before; only the implicit $HOME lookup is gated.
	if implicitPath && geteuid() == 0 {
		if uid, ok := fileOwner(cfgFile); ok && uid != 0 {
			cfg := defaults
			return &cfg, nil
		}
	}

	v.SetDefault("thresholds.disk_warn_pct", defaults.Thresholds.DiskWarnPct)
	v.SetDefault("thresholds.disk_crit_pct", defaults.Thresholds.DiskCritPct)
	v.SetDefault("thresholds.ram_warn_pct", defaults.Thresholds.RAMWarnPct)
	v.SetDefault("thresholds.ram_crit_pct", defaults.Thresholds.RAMCritPct)
	v.SetDefault("thresholds.cpu_load_warn_multiplier", defaults.Thresholds.CPULoadWarnMultiplier)
	v.SetDefault("thresholds.cpu_load_crit_multiplier", defaults.Thresholds.CPULoadCritMultiplier)
	v.SetDefault("thresholds.io_util_warn_pct", defaults.Thresholds.IOUtilWarnPct)
	v.SetDefault("thresholds.io_util_crit_pct", defaults.Thresholds.IOUtilCritPct)
	v.SetDefault("thresholds.io_await_warn_ms", defaults.Thresholds.IOAwaitWarnMs)
	v.SetDefault("thresholds.io_await_crit_ms", defaults.Thresholds.IOAwaitCritMs)
	v.SetDefault("thresholds.swap_warn_pct", defaults.Thresholds.SwapWarnPct)
	v.SetDefault("thresholds.swap_crit_pct", defaults.Thresholds.SwapCritPct)
	v.SetDefault("thresholds.ntp_warn_ms", defaults.Thresholds.NTPWarnMs)
	v.SetDefault("thresholds.ntp_crit_ms", defaults.Thresholds.NTPCritMs)
	v.SetDefault("thresholds.fd_warn_pct", defaults.Thresholds.FDWarnPct)
	v.SetDefault("thresholds.fd_crit_pct", defaults.Thresholds.FDCritPct)
	v.SetDefault("logs.since_minutes", defaults.Logs.SinceMinutes)

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) || os.IsNotExist(err) {
			// No config file at all — the documented default UX. Silent.
			cfg := defaults
			return &cfg, nil
		}
		// internal-config-01-01: a config file that EXISTS but couldn't be
		// read (bad permissions) or parsed (malformed YAML) was previously
		// masked identically to "no config file" — defaults with a nil
		// error — silently discarding whatever custom thresholds/services
		// the user believed were active. Still fall back to defaults so
		// callers keep working (dsd must never fail a health run over a
		// config typo), but return the error too so the caller can disclose
		// it instead of a false "using your config" read.
		cfg := defaults
		return &cfg, fmt.Errorf("reading config %s: %w", v.ConfigFileUsed(), err)
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func Default() *Config { d := defaults; return &d }

// Validate rejects a Config whose values could not have come from a sane
// hand-edited or generated file: YAML special floats (.nan, .inf, a negative
// percentage/multiplier) in Thresholds, negative counts or out-of-range
// ports in Security, and any Services entry missing a required field or
// carrying a port outside 1-65535. v.Unmarshal has no validation layer of
// its own, and Config is a public, reusable API — this is the one place
// positioned to catch a bad value before it fans out to every consumer that
// trusts these fields as pre-validated.
func (c Config) Validate() error {
	if err := c.Thresholds.validate(); err != nil {
		return fmt.Errorf("thresholds: %w", err)
	}
	if err := c.Security.validate(); err != nil {
		return fmt.Errorf("security: %w", err)
	}
	for i, s := range c.Services {
		if err := s.validate(); err != nil {
			return fmt.Errorf("services[%d]: %w", i, err)
		}
	}
	return nil
}

// validate rejects a non-finite (NaN/Inf) or negative threshold. Thresholds
// are percentages/multipliers/millisecond durations — none are meaningful
// negative, and a NaN/Inf silently breaks every WARN/CRIT comparison that
// reads it.
func (t ThresholdConfig) validate() error {
	fields := []struct {
		name string
		v    float64
	}{
		{"disk_warn_pct", t.DiskWarnPct}, {"disk_crit_pct", t.DiskCritPct},
		{"ram_warn_pct", t.RAMWarnPct}, {"ram_crit_pct", t.RAMCritPct},
		{"cpu_load_warn_multiplier", t.CPULoadWarnMultiplier}, {"cpu_load_crit_multiplier", t.CPULoadCritMultiplier},
		{"io_util_warn_pct", t.IOUtilWarnPct}, {"io_util_crit_pct", t.IOUtilCritPct},
		{"io_await_warn_ms", t.IOAwaitWarnMs}, {"io_await_crit_ms", t.IOAwaitCritMs},
		{"swap_warn_pct", t.SwapWarnPct}, {"swap_crit_pct", t.SwapCritPct},
		{"ntp_warn_ms", t.NTPWarnMs}, {"ntp_crit_ms", t.NTPCritMs},
		{"fd_warn_pct", t.FDWarnPct}, {"fd_crit_pct", t.FDCritPct},
	}
	for _, f := range fields {
		if math.IsNaN(f.v) || math.IsInf(f.v, 0) {
			return fmt.Errorf("%s: must be a finite number, got %v", f.name, f.v)
		}
		if f.v < 0 {
			return fmt.Errorf("%s: must be >= 0, got %v", f.name, f.v)
		}
	}
	return nil
}

// validate rejects a negative login-count threshold or an allowed port
// outside the valid 1-65535 range.
func (s SecurityConfig) validate() error {
	if s.SSHFailedLoginWarn < 0 {
		return fmt.Errorf("ssh_failed_login_warn: must be >= 0, got %d", s.SSHFailedLoginWarn)
	}
	if s.SSHFailedLoginCrit < 0 {
		return fmt.Errorf("ssh_failed_login_crit: must be >= 0, got %d", s.SSHFailedLoginCrit)
	}
	for _, p := range s.AllowedPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("allowed_ports: %d out of range 1-65535", p)
		}
	}
	return nil
}

// validate rejects a ServiceConfig entry missing its name/host or carrying a
// port outside the valid 1-65535 range. ServiceConfig is consumed downstream
// by internal/collectors — an out-of-range port or empty host reaching that
// layer as "pre-validated" would misbehave silently rather than erroring
// loudly at config-load time.
func (s ServiceConfig) validate() error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	if s.Host == "" {
		return fmt.Errorf("host is required (service %q)", s.Name)
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("port %d out of range 1-65535 (service %q)", s.Port, s.Name)
	}
	return nil
}
