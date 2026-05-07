package config

import (
	"fmt"
	"os"
	"path/filepath"

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

func Load(cfgFile string) (*Config, error) {
	v := viper.New()
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, _ := os.UserHomeDir()
		v.SetConfigFile(filepath.Join(home, ".dsd.yaml"))
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
		cfg := defaults
		return &cfg, nil
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

func Default() *Config { d := defaults; return &d }
