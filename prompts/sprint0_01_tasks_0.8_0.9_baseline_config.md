# DashDiag — Sprint 0: Tasks 0.8 + 0.9
## Baseline system + Config layer
## Paste each block into Claude Code

---

## Context (already implemented — do not touch)
- internal/models/ — all structs
- internal/output/ — tty.go, progress.go, formatter.go
- internal/runner/ — runner.go with Collector interface and RunAll
- internal/analysis/ — heuristics.go, thresholds.go
- internal/platform/ — cloud.go, container.go, platform.go
- internal/tips/ — state.go, tips.go, milestones.go
- cmd/root.go — root command with all flags

After every prompt: `go build ./...` must pass before moving to the next.

---

## TASK 0.8 — Baseline system (--diff and --since-deploy)

Paste this into Claude Code:

```
Create the baseline system. Two files.

FILE 1: internal/baseline/baseline.go

package baseline

import (
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"

    "github.com/keyorixhq/dashdiag/internal/models"
    "github.com/keyorixhq/dashdiag/internal/runner"
    "github.com/keyorixhq/dashdiag/internal/version"
)

type Snapshot struct {
    Hostname  string        `json:"hostname"`
    Timestamp time.Time     `json:"timestamp"`
    Version   string        `json:"version"`
    Checks    []CheckResult `json:"checks"`
}

type CheckResult struct {
    Name   string      `json:"name"`
    Status string      `json:"status"`
    Value  string      `json:"value"`
    Raw    interface{} `json:"raw,omitempty"`
}

type DiffEntry struct {
    Name         string
    Before       string
    After        string
    StatusChange string // "OK->WARN", "WARN->CRIT", "CRIT->OK" etc
    Changed      bool
    Improved     bool  // status got better
}

func baselineDir() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".dsd", "baselines")
}

func latestPath(hostname string) string {
    return filepath.Join(baselineDir(), hostname+"-latest.json")
}

func prevPath(hostname string) string {
    return filepath.Join(baselineDir(), hostname+"-prev.json")
}

// SaveBaseline saves snapshot atomically and rotates latest to prev.
func SaveBaseline(snap *Snapshot) error {
    dir := baselineDir()
    if err := os.MkdirAll(dir, 0755); err != nil {
        return fmt.Errorf("creating baseline dir: %w", err)
    }
    data, err := json.MarshalIndent(snap, "", "  ")
    if err != nil {
        return fmt.Errorf("marshalling snapshot: %w", err)
    }
    tsFile := filepath.Join(dir, snap.Hostname+"-"+snap.Timestamp.Format("20060102-150405")+".json")
    tmp, err := os.CreateTemp(dir, ".snap-*.tmp")
    if err != nil { return fmt.Errorf("creating temp file: %w", err) }
    tmpName := tmp.Name()
    defer os.Remove(tmpName)
    if _, err := tmp.Write(data); err != nil { tmp.Close(); return err }
    if err := tmp.Close(); err != nil { return err }
    if err := os.Rename(tmpName, tsFile); err != nil { return err }
    latest := latestPath(snap.Hostname)
    if _, err := os.Stat(latest); err == nil {
        os.Rename(latest, prevPath(snap.Hostname))
    }
    tmp2, _ := os.CreateTemp(dir, ".latest-*.tmp")
    tmp2Name := tmp2.Name()
    defer os.Remove(tmp2Name)
    tmp2.Write(data)
    tmp2.Close()
    return os.Rename(tmp2Name, latest)
}

// LoadBaseline loads a snapshot.
// path="-" reads stdin, path="" loads prev baseline, path=<file> reads that file.
func LoadBaseline(path string) (*Snapshot, error) {
    var data []byte
    var err error
    switch path {
    case "-":
        data, err = io.ReadAll(os.Stdin)
    case "":
        hostname, _ := os.Hostname()
        data, err = os.ReadFile(prevPath(hostname))
    default:
        data, err = os.ReadFile(path)
    }
    if err != nil { return nil, fmt.Errorf("reading baseline: %w", err) }
    var snap Snapshot
    if err := json.Unmarshal(data, &snap); err != nil {
        return nil, fmt.Errorf("parsing baseline: %w", err)
    }
    return &snap, nil
}

// BuildSnapshot builds a Snapshot from runner results and insights.
func BuildSnapshot(results []runner.Result, insights []models.Insight) *Snapshot {
    hostname, _ := os.Hostname()
    snap := &Snapshot{
        Hostname:  hostname,
        Timestamp: time.Now(),
        Version:   version.Version,
    }
    for _, r := range results {
        cr := CheckResult{Name: r.Name, Raw: r.Data}
        cr.Status = "OK"
        for _, ins := range insights {
            if ins.Check == r.Name {
                cr.Status = ins.Level
                cr.Value = ins.Message
                break
            }
        }
        snap.Checks = append(snap.Checks, cr)
    }
    return snap
}

// ComputeDiff compares two snapshots. Returns degraded first, improved second, unchanged last.
func ComputeDiff(before, after *Snapshot) []DiffEntry {
    beforeMap := make(map[string]CheckResult)
    for _, c := range before.Checks {
        beforeMap[c.Name] = c
    }
    statusOrder := map[string]int{"OK": 0, "INFO": 0, "WARN": 1, "CRIT": 2}
    var degraded, improved, unchanged []DiffEntry
    for _, ac := range after.Checks {
        bc := beforeMap[ac.Name]
        d := DiffEntry{
            Name:         ac.Name,
            Before:       bc.Status + " " + bc.Value,
            After:        ac.Status + " " + ac.Value,
            StatusChange: bc.Status + "->" + ac.Status,
            Changed:      bc.Status != ac.Status,
            Improved:     statusOrder[ac.Status] < statusOrder[bc.Status],
        }
        switch {
        case d.Changed && !d.Improved:
            degraded = append(degraded, d)
        case d.Changed && d.Improved:
            improved = append(improved, d)
        default:
            unchanged = append(unchanged, d)
        }
    }
    var result []DiffEntry
    result = append(result, degraded...)
    result = append(result, improved...)
    result = append(result, unchanged...)
    return result
}

---

FILE 2: internal/baseline/since_deploy.go

package baseline

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"
    "os/exec"

    "github.com/keyorixhq/dashdiag/internal/output"
)

// DetectLastDeployTime finds the last time a service was restarted.
func DetectLastDeployTime() (time.Time, string, error) {
    // Signal 1: systemd ActiveEnterTimestamp
    for _, svc := range []string{"nginx", "apache2", "caddy", "postgres", "mysqld",
        "redis", "redis-server", "docker", "containerd", "node", "gunicorn"} {
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        out, err := exec.CommandContext(ctx, "systemctl", "show", svc,
            "--property=ActiveEnterTimestamp", "--value").Output()
        cancel()
        if err != nil || strings.TrimSpace(string(out)) == "" { continue }
        t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(string(out)))
        if err != nil { continue }
        return t, svc + ".service restarted", nil
    }
    // Signal 2: newest process start time from /proc
    if t, name, err := newestProcStart(2 * time.Hour); err == nil {
        return t, name + " process started", nil
    }
    // Signal 3: git last commit
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    out, err := exec.CommandContext(ctx, "git", "log", "-1", "--format=%ct").Output()
    cancel()
    if err == nil {
        if ts, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
            return time.Unix(ts, 0), "git: last commit", nil
        }
    }
    return time.Time{}, "", fmt.Errorf("no deploy signal found")
}

func newestProcStart(maxAge time.Duration) (time.Time, string, error) {
    entries, err := filepath.Glob("/proc/[0-9]*/stat")
    if err != nil { return time.Time{}, "", err }
    boot := getBootTime()
    var newest time.Time
    var newestName string
    for _, entry := range entries {
        data, err := os.ReadFile(entry)
        if err != nil { continue }
        fields := strings.Fields(string(data))
        if len(fields) < 22 { continue }
        name := strings.Trim(fields[1], "()")
        startTicks, err := strconv.ParseFloat(fields[21], 64)
        if err != nil { continue }
        startTime := boot.Add(time.Duration(startTicks/100) * time.Second)
        age := time.Since(startTime)
        if age > maxAge || age < 0 { continue }
        if startTime.After(newest) { newest = startTime; newestName = name }
    }
    if newest.IsZero() { return time.Time{}, "", fmt.Errorf("no recent process") }
    return newest, newestName, nil
}

func getBootTime() time.Time {
    data, err := os.ReadFile("/proc/stat")
    if err != nil { return time.Now().Add(-24 * time.Hour) }
    for _, line := range strings.Split(string(data), "\n") {
        if strings.HasPrefix(line, "btime ") {
            ts, _ := strconv.ParseInt(strings.TrimPrefix(line, "btime "), 10, 64)
            return time.Unix(ts, 0)
        }
    }
    return time.Now().Add(-24 * time.Hour)
}

// FindBaselineBeforeTime returns the newest baseline saved before time t.
func FindBaselineBeforeTime(t time.Time, hostname string) (*Snapshot, error) {
    dir := baselineDir()
    entries, err := filepath.Glob(filepath.Join(dir, hostname+"-2*.json"))
    if err != nil || len(entries) == 0 {
        return nil, fmt.Errorf("no baselines found for %s", hostname)
    }
    var best *Snapshot
    var bestTime time.Time
    for _, p := range entries {
        info, err := os.Stat(p)
        if err != nil { continue }
        if info.ModTime().Before(t) && info.ModTime().After(bestTime) {
            snap, err := LoadBaseline(p)
            if err != nil { continue }
            best = snap; bestTime = info.ModTime()
        }
    }
    if best == nil {
        return nil, fmt.Errorf("no baseline found before %s", t.Format(time.RFC3339))
    }
    return best, nil
}

// RunSinceDeployDiff is the --since-deploy entry point.
func RunSinceDeployDiff(mode output.OutputMode) error {
    deployTime, signal, err := DetectLastDeployTime()
    if err != nil {
        fmt.Println("info:  No deploy signal detected.")
        fmt.Println("       Run dsd health before your next deploy to enable this check.")
        fmt.Println("       Or: dsd health --diff  to compare against your last run.")
        return nil
    }
    hostname, _ := os.Hostname()
    _, err = FindBaselineBeforeTime(deployTime, hostname)
    if err != nil {
        mins := int(time.Since(deployTime).Minutes())
        fmt.Printf("info:  No pre-deploy baseline found (%s, %d min ago).\n", signal, mins)
        fmt.Println("       Run dsd health before your next deploy to enable this check.")
        return nil
    }
    mins := int(time.Since(deployTime).Minutes())
    fmt.Printf("Changes since last deploy (%s, %d min ago)\n\n", signal, mins)
    return nil
}

---

FILE 3: internal/baseline/baseline_test.go

Write table-driven tests using t.TempDir() for all file operations:
  TestSaveLoad_RoundTrip: save then load, compare fields
  TestComputeDiff_OneChange: before Status="OK", after Status="WARN" -> Changed=true
  TestComputeDiff_NoChange: identical snapshots -> all Changed=false
  TestComputeDiff_Improved: before="CRIT", after="OK" -> Improved=true

Run: go build ./internal/baseline/... && go test ./internal/baseline/... -v -race
```

---

## TASK 0.9 — Config layer

Paste this into Claude Code:

```
Create internal/config/config.go with all defaults from SPEC.md thresholds table.

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
    v.SetDefault("thresholds.disk_warn_pct",            defaults.Thresholds.DiskWarnPct)
    v.SetDefault("thresholds.disk_crit_pct",            defaults.Thresholds.DiskCritPct)
    v.SetDefault("thresholds.ram_warn_pct",             defaults.Thresholds.RAMWarnPct)
    v.SetDefault("thresholds.ram_crit_pct",             defaults.Thresholds.RAMCritPct)
    v.SetDefault("thresholds.cpu_load_warn_multiplier", defaults.Thresholds.CPULoadWarnMultiplier)
    v.SetDefault("thresholds.cpu_load_crit_multiplier", defaults.Thresholds.CPULoadCritMultiplier)
    v.SetDefault("thresholds.io_util_warn_pct",         defaults.Thresholds.IOUtilWarnPct)
    v.SetDefault("thresholds.io_util_crit_pct",         defaults.Thresholds.IOUtilCritPct)
    v.SetDefault("thresholds.io_await_warn_ms",         defaults.Thresholds.IOAwaitWarnMs)
    v.SetDefault("thresholds.io_await_crit_ms",         defaults.Thresholds.IOAwaitCritMs)
    v.SetDefault("thresholds.swap_warn_pct",            defaults.Thresholds.SwapWarnPct)
    v.SetDefault("thresholds.swap_crit_pct",            defaults.Thresholds.SwapCritPct)
    v.SetDefault("thresholds.ntp_warn_ms",              defaults.Thresholds.NTPWarnMs)
    v.SetDefault("thresholds.ntp_crit_ms",              defaults.Thresholds.NTPCritMs)
    v.SetDefault("thresholds.fd_warn_pct",              defaults.Thresholds.FDWarnPct)
    v.SetDefault("thresholds.fd_crit_pct",              defaults.Thresholds.FDCritPct)
    v.SetDefault("logs.since_minutes",                  defaults.Logs.SinceMinutes)

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

Also run: go get github.com/spf13/viper@v1.18.2 if not in go.mod.

Run: go build ./internal/config/... && go test ./internal/config/... -v -race
```
