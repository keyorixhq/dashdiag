# DashDiag — Complete Implementation Plan
## Claude Code Execution Guide
### Paired with SPEC.md v48.0

---

## HOW TO USE THIS PLAN

Work through tasks in order. After each task:
1. `go build ./...` — must compile with zero errors
2. `go test ./... -race` — must pass
3. Commit before moving to next task

**Already implemented (do not touch):**
- internal/models/ (all model files)
- internal/output/ (tty.go, progress.go, formatter.go)
- internal/runner/ (runner.go, Collector interface, RunAll)
- internal/analysis/ (heuristics.go, thresholds.go)
- internal/platform/ (cloud.go, container.go, platform.go)
- internal/tips/ (state.go, tips.go, milestones.go)

---

## SPRINT 0 — FOUNDATION

### TASK 0.8 — Baseline system

**Objective:** `--diff` and `--since-deploy` work. Baselines save atomically.

**Prompt for Claude Code:**
```
Read SPEC.md §19b --diff section and the since_deploy.go spec.

Create internal/baseline/baseline.go:

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
    StatusChange string
    Changed      bool
    Improved     bool
}

func baselineDir() string  // ~/.dsd/baselines/
func SaveBaseline(snap *Snapshot) error
    // atomic: temp file + os.Rename
    // rotate: copy latest→prev, then write new→latest

func LoadBaseline(path string) (*Snapshot, error)
    // path="-"  → read os.Stdin
    // path!=""  → read explicit file
    // path==""  → load prev baseline from ~/.dsd/baselines/<hostname>-prev.json

func BuildSnapshot(results []runner.Result, insights []models.Insight) *Snapshot
func ComputeDiff(before, after *Snapshot) []DiffEntry
    // Changed = status differs OR value changed meaningfully
    // Sort: CRIT changes → WARN changes → improvements → unchanged

Create internal/baseline/since_deploy.go:

func DetectLastDeployTime() (time.Time, string, error)
    // Try in order:
    // 1. systemctl show nginx,apache2,postgres,mysql,redis,docker --property=ActiveEnterTimestamp
    // 2. Scan /proc/[PID]/stat for most recently started process (uptime < 2h)
    // 3. git log -1 --format=%ct in current directory
    // Return first that succeeds. Return error if all fail.

func FindBaselineBeforeTime(t time.Time, hostname string) (*Snapshot, error)
    // Scan ~/.dsd/baselines/<hostname>-*.json
    // Return newest whose Timestamp is before t

func RunSinceDeployDiff(mode output.OutputMode) error
    // 1. DetectLastDeployTime
    // 2. If no signal: print guidance, return nil (not error)
    // 3. FindBaselineBeforeTime
    // 4. If no baseline: print guidance, return nil
    // 5. Run health snapshot, ComputeDiff, print

Graceful messages when data missing:
  No signal:   "ℹ️  No deploy signal detected.\n    Run dsd health before your next deploy."
  No baseline: "ℹ️  No pre-deploy baseline found (<signal> N min ago).\n    Run dsd health before your next deploy."

Tests (baseline_test.go):
  TestSaveLoad_RoundTrip: save then load, compare
  TestComputeDiff_OneChange: before has OK memory, after has WARN memory
  TestComputeDiff_NoChange: identical snapshots → all Changed=false
  Use t.TempDir() for all file writes
```

**Verification:**
```bash
go build ./internal/baseline/...
go test ./internal/baseline/... -v -race
```

---

### TASK 0.9 — Config layer

**Objective:** `~/.dsd.yaml` loads with viper. Defaults match SPEC.md §12 thresholds.

**Prompt for Claude Code:**
```
Create internal/config/config.go:

package config

import (
    "github.com/spf13/viper"
    "os"
    "path/filepath"
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
    IOUtilWarnPct         float64 `yaml:"io_util_warn_pct"         mapstructure:"io_util_warn_pct"`
    IOUtilCritPct         float64 `yaml:"io_util_crit_pct"         mapstructure:"io_util_crit_pct"`
    SwapWarnPct           float64 `yaml:"swap_warn_pct"            mapstructure:"swap_warn_pct"`
    SwapCritPct           float64 `yaml:"swap_crit_pct"            mapstructure:"swap_crit_pct"`
    NTPWarnMs             float64 `yaml:"ntp_warn_ms"              mapstructure:"ntp_warn_ms"`
    NTPCritMs             float64 `yaml:"ntp_crit_ms"              mapstructure:"ntp_crit_ms"`
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
        IOUtilWarnPct:         60.0,
        IOUtilCritPct:         85.0,
        SwapWarnPct:           20.0,
        SwapCritPct:           60.0,
        NTPWarnMs:             100.0,
        NTPCritMs:             500.0,
    },
    Logs:     LogsConfig{SinceMinutes: 60},
    Security: SecurityConfig{AllowedPorts: []int{22, 80, 443, 8080, 5432}, SSHFailedLoginWarn: 20, SSHFailedLoginCrit: 50},
}

func Load(cfgFile string) (*Config, error)
    // if cfgFile empty: look for ~/.dsd.yaml
    // use viper to load, unmarshal into Config
    // if file not found: return Default() (not error)

func Default() *Config {
    d := defaults
    return &d
}
```

**Verification:**
```bash
go build ./internal/config/...
go test ./internal/config/... -v
```

---

### TASK 0.10 — All 12 health collectors

**Objective:** Every collector returns correct data. Parser tests pass. Fuzz tests run.

**Prompt for Claude Code (part A — interface + cpu + memory + swap):**
```
Read .cursorrules section "DASHDIAG-SPECIFIC PATTERNS" before writing any code.

Create internal/collectors/collector.go — Collector interface matching runner.Collector:
package collectors
import ("context"; "time")
type Collector interface {
    Name()    string
    Timeout() time.Duration
    Collect(ctx context.Context) (interface{}, error)
}

Create internal/collectors/cpu.go:
  Name: "CPU", Timeout: 500ms
  
  Injectable reader pattern (MANDATORY — enables testing):
  type cpuReader interface {
      loadAvg() (io.ReadCloser, error)
      stat() (io.ReadCloser, error)
  }
  type CPUCollector struct {
      reader       cpuReader
      ContainerCtx platform.ContainerContext
  }
  func NewCPUCollector(ctx platform.ContainerContext) *CPUCollector
  
  Pure parsers (no OS calls — injectable in tests):
  func parseLoadAvg(r io.Reader) (load1, load5, load15 float64, err error)
  func parseCPUStat(r io.Reader) (idle, total uint64, err error)
  
  Collect():
  - Read /proc/loadavg via reader.loadAvg()
  - macOS fallback: exec sysctl kern.loadavg
  - Two reads of /proc/stat with 500ms select gap for usage%
  - ContainerCtx: if CPULimitCores > 0, use as effective NumCPU
  - Return *models.CPUInfo (NO Status field — analysis sets that)

Create testdata/fixtures/cpu/linux_healthy.txt with real /proc/loadavg content:
  0.52 0.43 0.32 3/412 8932

Create internal/collectors/cpu_test.go:
  TestParseLoadAvg (table-driven, t.Parallel())
  FuzzParseLoadAvg (fuzz test — must never panic)

Create internal/collectors/memory.go:
  Name: "Memory", Timeout: 200ms
  
  type MemoryCollector struct {
      ContainerCtx platform.ContainerContext
      meminfoPath  string  // "/proc/meminfo" — injectable for tests
  }
  
  func parseMeminfo(r io.Reader) (map[string]uint64, error)
  // parse lines like "MemTotal:       16384000 kB"
  // return map of field names to kB values
  
  Collect():
  - gopsutil/v3/mem VirtualMemory() for basic stats
  - parseMeminfo for: MemTotal, MemFree, MemAvailable, Slab, CommitLimit, Committed_AS
  - OverCommitted = Committed_AS > CommitLimit
  - ContainerCtx: if MemLimitMB > 0, use as effective total
  - macOS: gopsutil works, /proc/meminfo not available → Slab/CommitLimit = -1
  - Return *models.MemoryInfo

Create internal/collectors/swap.go:
  Name: "Swap", Timeout: 3s
  
  func parseVMStat(r io.Reader) (pswpin, pswpout uint64, err error)
  // parse pswpin and pswpout fields from /proc/vmstat
  
  Collect():
  - Read /proc/swaps for configured swap
  - TWO reads of /proc/vmstat with 1s gap (use select + time.After)
  - Compute per-second delta for SwapInPerSec, SwapOutPerSec
  - Check /sys/block/zram0/stat existence for ZramPresent
  - macOS: exec vm_stat, parse "Pages swapped in/out" (single snapshot, no rate)
  - Return *models.SwapInfo

Create fixture files and fuzz tests for memory and swap parsers.
```

**Prompt for Claude Code (part B — disk + io + network_quick):**
```
Create internal/collectors/disk.go:
  Name: "Disk", Timeout: 1s
  
  func readMounts(r io.Reader) ([]string, error)
  // parse /proc/mounts, return mount point paths
  // skip: tmpfs, devtmpfs, overlay, squashfs, proc, sysfs, cgroup, devpts
  
  Collect():
  - Parse /proc/mounts via injectable reader
  - For each mount point: syscall.Statfs() for size/free/inodes
  - Return []models.DiskInfo (one per filesystem, skip pseudo filesystems)
  - Each DiskInfo: Device, MountPoint, TotalGB, FreeGB, UsedPct, InodesUsedPct
  - macOS: same approach (Statfs works on macOS)

Create internal/collectors/io.go:
  Name: "IO", Timeout: 4s
  
  type diskStats struct { reads, writes, readSectors, writeSectors, ioTime uint64 }
  func parseDiskstats(r io.Reader) (map[string]diskStats, error)
  // parse /proc/diskstats fields 3-13 (field indices per kernel docs)
  // only physical devices: name starts with sd, nvme, vd, xvd
  
  Collect():
  - TWO reads of /proc/diskstats with 1s gap
  - Compute per-second deltas
  - IsRotational: read /sys/block/<dev>/queue/rotational (1=HDD, 0=SSD)
  - UtilPct: ioTime delta / 1000 * 100
  - AwaitMs: (readTime+writeTime)delta / max(1, reads+writes delta)
  - macOS: gopsutil/v3/disk IOCounters() — no rotational detection
  - Return []models.IOInfo

Create internal/collectors/network_quick.go:
  Name: "Network", Timeout: 3s
  
  Collect() — all pings run concurrently:
  - Interfaces: gopsutil/v3/net Interfaces(), filter loopback + virtual
    skip: lo, docker0, br-, veth*, virbr*, bond* sub-interfaces
  - Gateway: detect via net.InterfaceAddrs() / route parsing
  - Ping gateway: 3 ICMP pings via go-ping, 500ms timeout each, run concurrently
  - Ping 8.8.8.8: 3 pings concurrent with gateway
  - DNS: net.LookupHost("github.com") with 2s timeout
  - CLOSE_WAIT: gopsutil net.Connections("tcp"), count CLOSE_WAIT state
  - Total timeout: 3s — all work concurrent, no sequential blocking
  - macOS: same code path (go-ping works on macOS)
  - Return *models.NetworkInfo
```

**Prompt for Claude Code (part C — clock + fdlimits + processes + systemd + sysctl + mac_policy):**
```
Create these 6 remaining collectors:

internal/collectors/clock.go (Name:"Clock", Timeout:2s):
  func parseTimedatectl(r io.Reader) (synced bool, offsetMs float64, err error)
  // parse "NTPSynchronized=yes" and "NTPOffsetUsec=12345"
  Linux:
  - exec timedatectl show --property=NTPSynchronized,NTPOffset (via ctx)
  - fallback: exec chronyc tracking, parse "System time offset"
  macOS:
  - exec systemsetup -getusingnetworktime
  - sync state only, OffsetMs = -1
  Return *models.ClockInfo

internal/collectors/fdlimits.go (Name:"FDLimits", Timeout:1s):
  - System: read /proc/sys/fs/file-nr → OpenCount, MaxCount
  - Per-process hot: scan /proc/[0-9]*/limits for "Max open files" soft limit
    count /proc/[PID]/fd/* entries (os.ReadDir)
    flag if fd_count/soft_limit > 0.8
  - Deleted-but-open: /proc/[PID]/fd/* symlinks ending in "(deleted)"
  - macOS: use sysctl kern.maxfiles for MaxCount
  Return *models.FDInfo

internal/collectors/processes.go (Name:"Processes", Timeout:2s):
  func parseProcStat(r io.Reader) (state string, err error)
  // parse 3rd field of /proc/[PID]/stat
  - Scan /proc/[0-9]* directories
  - Read /proc/[PID]/stat, parse state field
  - Z = zombie, D = uninterruptible sleep
  - For D-state: read /proc/[PID]/wchan for kernel function name
  - Read /proc/[PID]/comm for process name
  Return []models.ProcessState

internal/collectors/systemd.go (Name:"Systemd", Timeout:3s):
  - Check SystemdAvailable() from platform package first
  - exec systemctl list-units --state=failed --no-legend --no-pager (via ctx)
  - exec systemctl list-units --state=activating --no-legend --no-pager
  - Parse output: extract unit names
  - macOS / no systemd: return &models.SystemdInfo{Available: false}
  Return *models.SystemdInfo

internal/collectors/sysctl.go (Name:"Sysctl", Timeout:1s):
  - /proc/sys/net/core/somaxconn (Linux) or sysctl kern.ipc.somaxconn (macOS)
  - /proc/sys/kernel/pid_max
  - /proc/sys/vm/swappiness (Linux only)
  - Current PID count: count entries in /proc matching [0-9]+
  Return *models.SysctlInfo

internal/collectors/mac_policy.go (Name:"MACPolicy", Timeout:5s):
  - SELinux: exec getenforce (via ctx), parse "Enforcing"/"Permissive"/"Disabled"
    AVC denials: if SELinux enforcing, count "avc:  denied" in last hour via journalctl
  - AppArmor: read /sys/module/apparmor/parameters/enabled
  - macOS: return &models.MACPolicyInfo{} (not applicable)
  Return *models.MACPolicyInfo

For EACH collector create:
- Parser unit test (table-driven, t.Parallel())
- Fuzz test for any parser that reads structured text
- testdata/fixtures/<name>/linux_healthy.txt with real /proc content
```

**Verification:**
```bash
go build ./internal/collectors/...
go test ./internal/collectors/... -v -race -count=1 -timeout 60s
```

---

### TASK 0.11 — Render layer

**Objective:** Health output renders correctly in human/plain/json modes. Golden file tests pass.

**Prompt for Claude Code:**
```
Read .cursorrules "Lipgloss colours must be adaptive" before writing any code.

Create internal/render/styles.go:
ALL lipgloss styles defined here ONLY. Use AdaptiveColor everywhere.

var (
    StyleOK   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#2E7D32", Dark: "#66BB6A"})
    StyleWarn = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#E65100", Dark: "#FFB74D"})
    StyleCrit = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#B71C1C", Dark: "#EF5350"})
    StyleInfo = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#1565C0", Dark: "#64B5F6"})
    StyleDim  = lipgloss.NewStyle().Faint(true)
    StyleBold = lipgloss.NewStyle().Bold(true)
)

Create internal/render/health.go:

type Renderer struct{ mode output.OutputMode }
func NewRenderer(mode output.OutputMode) *Renderer

func (r *Renderer) PrintAll(results []runner.Result, insights []models.Insight)
  // For each result: format one line per check
  // Human: "CPU        ✅  load 0.52 / 4 cores (13%)"
  // Plain: "CPU        OK  load 0.52 / 4 cores (13%)"
  // Status icon from output.StatusIcon(status, mode)

func (r *Renderer) PrintSummary(insights []models.Insight) int
  // Returns exit code: 0=OK, 1=WARN, 2=CRIT
  // Human: "─────────────────────\n⚠️  1 warning — Memory..."
  // Followed by hint commands for each WARN/CRIT insight

func (r *Renderer) PrintContainerBanner(ctx platform.ContainerContext)
  // "ℹ️  Running inside container — host limits may differ"

Create internal/render/diff.go:
func PrintDiff(before, after *baseline.Snapshot, mode output.OutputMode) error
  Changes first (CRIT → WARN → improved), then collapsed unchanged line.
  "Unchanged (9 checks): CPU ✅  Disk ✅  ..."

Create internal/render/postmortem.go:
func RenderPostMortem(title string, snap *baseline.Snapshot, insights []models.Insight, mode output.OutputMode) string
  Always markdown output. Include: header table, issues, steps, timeline placeholder, footer.
  Footer: "*Generated by DashDiag — https://dashdiag.sh*"

Create internal/render/story.go:
func RenderStory(insights []models.Insight, snap *baseline.Snapshot) string
  Template-based — NO AI, NO API calls.
  One paragraph per active pattern. If all healthy: "All checks passed. System healthy."

Create internal/render/json.go:
func RenderJSON(results []runner.Result, insights []models.Insight) ([]byte, error)

Create internal/render/weekly.go:
func RenderWeekly(state *tips.State, period string) string
  Guard: < 7 days data → return info message.
  Format: terminal box with ChecksRun, DailyAvg, IssuesTotal, TimeSavedMin.
  Footer: "💡 See 90-day history: dashdiag.sh/teams"

Golden file tests:
  go test ./internal/render/... -update    (generate first time)
  go test ./internal/render/... -race      (verify)
```

---

### TASK 0.12 and 0.13 — TUI + cmd/health.go wiring

**Objective:** `dsd health` produces real output on your machine with all collectors running.

**Prompt for Claude Code:**
```
1. Create internal/tui/tui.go:
func IsTTY() bool  // os.Stdin file stat check

2. Create internal/tui/select.go:
SingleSelect and MultiSelect bubbletea components.
Both fall back to numbered text prompt when !IsTTY().
Used ONLY by dsd init and dsd hook install — nowhere else.

3. Create cmd/dsd/main.go if not present:
package main
import "github.com/keyorixhq/dashdiag/cmd"
func main() { cmd.Execute() }

4. Create cmd/health.go — WIRING ONLY, max 80 lines:

package cmd

func init() {
    rootCmd.AddCommand(healthCmd)
    healthCmd.AddCommand(healthDeepCmd)
}

var healthCmd = &cobra.Command{
    Use:   "health",
    Short: "System health check — CPU, memory, disk, network (~5s)",
    RunE:  runHealth,
}

var healthDeepCmd = &cobra.Command{
    Use:   "deep",
    Short: "Thorough health check including per-core CPU (~8s)",
    RunE:  runHealth,  // same for now — deep adds more collectors later
}

func runHealth(cmd *cobra.Command, args []string) error {
    ctx := context.Background()

    plain, _  := cmd.Flags().GetBool("plain")
    jsonOut,_ := cmd.Flags().GetBool("json")
    outputFmt := ""
    if jsonOut { outputFmt = "json" }
    mode := output.DetectMode(plain, false, outputFmt)

    ctrCtx   := platform.DetectContainerContext()
    cloudEnv := platform.DetectCloudEnvironment()
    cfg      := config.Default()

    // Load state — for re-engagement (BEFORE progress)
    state, _ := tips.LoadState()
    if state != nil {
        tips.MaybePrintReengagement(state, mode, version.Version)
    }

    // Progress — prints estimate BEFORE any collector work
    cols := buildHealthCollectors(ctrCtx)
    p := output.NewCommandProgress("System health", 5*time.Second, mode, len(cols))
    p.Start()
    defer p.Done()

    // Run all 12 collectors concurrently
    var results []runner.Result
    for r := range runner.RunAll(ctx, toRunnerCollectors(cols)) {
        p.Step(r.Name)
        results = append(results, r)
    }

    // Apply thresholds
    insights := analysis.ApplyThresholds(results, cfg, cloudEnv, ctrCtx)

    // Handle special output flags
    snap := baseline.BuildSnapshot(results, insights)

    sdFlag, _  := cmd.Flags().GetBool("since-deploy")
    diffFlag,_ := cmd.Flags().GetBool("diff")
    pmFlag, _  := cmd.Flags().GetString("post-mortem")

    if sdFlag {
        return baseline.RunSinceDeployDiff(mode)
    }
    if pmFlag != "" {
        fmt.Println(render.RenderPostMortem(pmFlag, snap, insights, mode))
        baseline.SaveBaseline(snap)
        return nil
    }

    // Render output
    renderer := render.NewRenderer(mode)
    if ctrCtx.InContainer {
        renderer.PrintContainerBanner(ctrCtx)
    }
    renderer.PrintAll(results, insights)

    if diffFlag {
        prev, err := baseline.LoadBaseline("")
        if err == nil {
            render.PrintDiff(prev, snap, mode)
        }
    }

    exitCode := renderer.PrintSummary(insights)
    baseline.SaveBaseline(snap)

    // Engagement — AFTER all output
    if state != nil {
        tips.MaybePrintMilestone(state, mode)
        tips.MaybePrintTip(state, mode)
        state.TotalRuns++
        if state.CommandCounts == nil {
            state.CommandCounts = make(map[string]int)
        }
        state.CommandCounts["health"]++
        state.Save()
    }

    if exitCode > 0 {
        os.Exit(exitCode)
    }
    return nil
}

func buildHealthCollectors(ctrCtx platform.ContainerContext) []collectors.Collector {
    return []collectors.Collector{
        collectors.NewCPUCollector(ctrCtx),
        collectors.NewMemoryCollector(ctrCtx),
        collectors.NewDiskCollector(),
        collectors.NewSwapCollector(),
        collectors.NewIOCollector(),
        collectors.NewNetworkQuickCollector(),
        collectors.NewClockCollector(),
        collectors.NewFDLimitsCollector(),
        collectors.NewProcessCollector(),
        collectors.NewSystemdCollector(),
        collectors.NewSysctlCollector(),
        collectors.NewMACPolicyCollector(),
    }
}

// toRunnerCollectors adapts collectors.Collector to runner.Collector
func toRunnerCollectors(cols []collectors.Collector) []runner.Collector {
    result := make([]runner.Collector, len(cols))
    for i, c := range cols {
        result[i] = c
    }
    return result
}

After writing cmd/health.go, run:
  go build ./...
  make build
  ./dist/dsd health
  ./dist/dsd health --json | python3 -m json.tool
  ./dist/dsd health --plain
  echo $?   // 0, 1, or 2

Fix any compilation errors. The binary MUST produce real health output before proceeding.
```

---

## SPRINT 0 DONE — VERIFICATION

```bash
go build ./...
go test ./... -race -count=1 -timeout 60s
./dist/dsd --version
./dist/dsd health
./dist/dsd health --json | python3 -m json.tool
./dist/dsd health --plain
./dist/dsd healt    # typo correction → suggests "dsd health"
git add -A && git commit -m "feat: Sprint 0 complete — dsd health working"
git tag v0.1.0
```

---

# SPRINT 1 — MAXIMUM VIRALITY

---

### TASK 1.1 and 1.2 — --diff, --since-deploy, --post-mortem, --story

**Prompt for Claude Code:**
```
Wire Sprint 1 viral flags into cmd/health.go (already partially wired in 0.13).
Complete the wiring and verify all four work end-to-end.

Add --story to root.go persistent flags:
  f.Bool("story", false, "human-readable narrative of system state")
  f.Bool("weekly", false, "show weekly usage report from state.json")

Wire --story in runHealth():
  storyFlag, _ := cmd.Flags().GetBool("story")
  if storyFlag {
      fmt.Println(render.RenderStory(insights, snap))
      return nil
  }

Wire --weekly in runHealth() (early return, before collectors):
  weeklyFlag, _ := cmd.Flags().GetBool("weekly")
  if weeklyFlag {
      state, _ := tips.LoadState()
      if state == nil || state.TotalRuns < 7 {
          fmt.Println("ℹ️  Not enough data yet. Run dsd health for 7+ days first.")
          return nil
      }
      fmt.Println(render.RenderWeekly(state, "weekly"))
      return nil
  }

Verify all these work:
  ./dist/dsd health --diff
  ./dist/dsd health --since-deploy
  ./dist/dsd health --post-mortem "test incident"
  ./dist/dsd health --story
  ./dist/dsd health --weekly
```

---

### TASK 1.3 and 1.4 — --qr, Pro labels, milestones wiring

**Prompt for Claude Code:**
```
1. Create internal/output/qr.go:

func PrintQRCode(url string, mode output.OutputMode) error
  - go get github.com/skip2/go-qrcode if not in go.mod
  - Generate QR as terminal Unicode art
  - Only activates when url != ""
  - Plain/non-TTY mode: print "Scan or visit: <url>" instead
  - Non-fatal if QR generation fails

2. Add ProLabel to internal/output/formatter.go:

func ProLabel(tier string, mode output.OutputMode) string
  // ModeHuman: lipgloss.NewStyle().Faint(true).Render("  ◆ " + tier)
  // ModePlain: "  [" + tier + "]"
  // JSON/YAML:  ""

3. Add ◆ labels to --help. In cmd/root.go, update long description:
  rootCmd.Long = "DashDiag (dsd) — one command instant system health overview.\n\n" +
      "◆ Team: dashdiag.sh/teams  |  ◆ Free account: dashdiag.sh/signup"

4. Verify milestones fire correctly (end-to-end):
  rm -f ~/.dsd/state.json
  for i in $(seq 1 10); do ./dist/dsd health 2>/dev/null; done
  # Should see NPS survey prompt on 10th run
  cat ~/.dsd/state.json  # verify total_runs: 10

5. Test tip rotation:
  go test ./internal/tips/... -v -race
```

---

# SPRINT 2 — HABIT FORMATION

---

### TASK 2.1 and 2.2 — dsd examples + dsd hook install

**Prompt for Claude Code:**
```
1. Create cmd/examples.go:

func init() { rootCmd.AddCommand(examplesCmd) }
var examplesCmd = &cobra.Command{
    Use:   "examples",
    Short: "Real-world usage workflows",
    RunE:  runExamples,
}
examplesCmd.Flags().Int("scenario", 0, "show only one scenario (1-6)")

func runExamples(cmd *cobra.Command, args []string) error
  Print the 6 scenarios from SPEC.md §19c Priority 6.
  scenario flag 0 = all, 1-6 = specific one.

2. Create internal/init/ directory:

internal/init/detector.go:
func DetectServerProfile() string
  Parse /proc/[0-9]*/comm (or ps aux on macOS)
  Return: "web" / "database" / "kubernetes" / "proxmox" / "general"

internal/init/firstrun.go:
func IsFirstRun() bool  // ~/.dsd/state.json does not exist

func RunWizard(mode output.OutputMode) error
  1. Detect profile
  2. Show menu: tui.SingleSelect (or numbered prompt if non-TTY)
  3. Write ~/.dsd.yaml with profile-specific thresholds
  4. Print "✅ Profile saved → running first check..." then return nil

Wire IsFirstRun in cmd/root.go RunE — before calling runHealth:
  if init_pkg.IsFirstRun() {
      init_pkg.RunWizard(mode)
  }

3. Create cmd/hook.go:

func init() { rootCmd.AddCommand(hookCmd) }
var hookCmd = &cobra.Command{ Use: "hook", Short: "Manage shell/CI hooks" }
var hookInstallCmd = &cobra.Command{
    Use: "install", Short: "Install DashDiag hooks",
    RunE: runHookInstall,
}
hookCmd.AddCommand(hookInstallCmd)
hookInstallCmd.Flags().Bool("dry-run", false, "show what would be written without writing")

6 hook options via tui.MultiSelect.
--dry-run shows diff-style preview.
After install: update state.HookInstalled = true, state.Save()
```

---

# SPRINT 3 — PHASE 1 COMPLETE

---

### TASK 3.1 and 3.2 — dsd net + dsd services

**Prompt for Claude Code:**
```
1. Create internal/collectors/network_deep.go:
  Name: "NetworkDeep", Timeout: 30s
  All of network_quick PLUS:
  - Jitter: 20-sample ping loop with time.After spacing
  - Bonds: read /proc/net/bonding/* if directory exists
  - Ethtool: exec ethtool <iface> (graceful if not installed)
  - Wireless: exec iw dev <iface> link (graceful if not installed)
  - Traceroute: only if packet_loss > 5% OR latency > 200ms (conditional)
    Use github.com/nxtrace/NTrace-core or exec traceroute as fallback

2. Create cmd/net.go:
  func init() {
      rootCmd.AddCommand(netCmd)
      netCmd.AddCommand(netDeepCmd)
  }
  dsd net      → NetworkQuickCollector, progress "Network snapshot" ~3s
  dsd net deep → NetworkDeepCollector, progress "Deep network analysis" ~30s
  Progress note on deep: "ℹ️  Traceroute only runs if a problem is detected"

3. Create internal/collectors/services.go:
  Name: "Services", Timeout: 10s
  Read services from config.Load().Services
  TCP: net.DialTimeout("tcp", "host:port", 5*time.Second)
  HTTP: http.Client with 10s timeout, check status code
  Empty state (no services in config) → return with guidance message

4. Create cmd/services.go wiring services collector.
  Empty state message:
    ℹ️  No services configured yet.
        Add to ~/.dsd.yaml:
        services:
          - name: nginx
            host: localhost
            port: 80
            protocol: http
        Or run: dsd init  to configure automatically.
```

---

### TASK 3.3 and 3.4 — Final Phase 1 verification + commit

**Prompt for Claude Code:**
```
Run full Phase 1 verification. Fix any failures before proceeding.

1. Build checks:
  go build ./...
  go vet ./...
  go test ./... -race -count=1 -timeout 60s

2. Binary checks:
  make build
  ./dist/dsd health
  ./dist/dsd health --json | python3 -m json.tool
  ./dist/dsd health --plain
  ./dist/dsd health --diff
  ./dist/dsd health --since-deploy
  ./dist/dsd health --story
  ./dist/dsd health --post-mortem "phase 1 test"
  ./dist/dsd net
  ./dist/dsd services
  ./dist/dsd examples
  ./dist/dsd hook install --dry-run
  ./dist/dsd healt     # typo → suggests "dsd health"
  ./dist/dsd --help | grep "◆"

3. Commit:
  git add -A
  git commit -m "feat: Phase 1 complete — dsd health, net, services all working"
  git tag v0.3.0-phase1
```

---

# SPRINT 4 — FIRST REVENUE

---

### TASK 4.1 and 4.2 — --watch mode + --yaml output

**Prompt for Claude Code:**
```
1. Wire --watch in cmd/health.go:

Add to healthCmd flags:
  healthCmd.Flags().Bool("watch", false, "refresh health check every 60 seconds")
  healthCmd.Flags().Duration("watch-interval", 60*time.Second, "watch refresh interval")

In runHealth(), after mode detection (early return):
  watchFlag, _ := cmd.Flags().GetBool("watch")
  if watchFlag {
      interval, _ := cmd.Flags().GetDuration("watch-interval")
      return runWatch(cmd, interval, ctrCtx, cloudEnv, cfg, mode)
  }

func runWatch(...) error {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    var prevSnap *baseline.Snapshot
    fmt.Fprintf(os.Stderr, "⚡ Watching (refresh every %s, Ctrl+C to exit)\n\n", interval)
    for {
        results, insights := runHealthOnce(ctx, ctrCtx, cloudEnv, cfg)
        snap := baseline.BuildSnapshot(results, insights)
        if prevSnap == nil {
            renderer := render.NewRenderer(mode)
            renderer.PrintAll(results, insights)
        } else {
            diffs := baseline.ComputeDiff(prevSnap, snap)
            changed := false
            for _, d := range diffs {
                if d.Changed { changed = true; break }
            }
            if changed {
                render.PrintDiff(prevSnap, snap, mode)
            } else {
                fmt.Printf("  %s  No changes — %s\n",
                    output.StatusIcon("OK", mode), time.Now().Format("15:04:05"))
            }
        }
        prevSnap = snap
        <-ticker.C
    }
}

2. Add ModeYAML to internal/output/tty.go:
  const ModeYAML OutputMode = 4  // add after ModeJSON
  Update DetectMode(): case outputFmt == "yaml": return ModeYAML

3. Add YAML rendering to internal/render/json.go (or new yaml.go):
  func RenderYAML(results []runner.Result, insights []models.Insight) ([]byte, error)
  // gopkg.in/yaml.v3 marshal of same struct as JSON

4. Wire in runHealth():
  if mode == output.ModeYAML {
      data, err := render.RenderYAML(results, insights)
      if err == nil { os.Stdout.Write(data) }
      return nil
  }

Verify:
  ./dist/dsd health --yaml
  ./dist/dsd health --watch &
  sleep 5 && kill %1
```

---

### TASK 4.3 — Final integration + git tag

**Prompt for Claude Code:**
```
Final end-to-end test of everything. Fix any failures.

./dist/dsd health
./dist/dsd health --json | python3 -m json.tool
./dist/dsd health --yaml
./dist/dsd health --plain
./dist/dsd health --diff
./dist/dsd health --since-deploy
./dist/dsd health --story
./dist/dsd health --post-mortem "final test"
./dist/dsd health --weekly
./dist/dsd health --watch &
sleep 3 && kill %1
./dist/dsd net
./dist/dsd net deep
./dist/dsd services
./dist/dsd examples
./dist/dsd examples --scenario 1
./dist/dsd hook install --dry-run
./dist/dsd healt   # typo correction
./dist/dsd --help | grep "◆"
make test-all
bash scripts/smoke-test.sh

Commit:
git add -A
git commit -m "feat: Sprint 4 complete — all flags working"
git tag v0.4.0
```

---

# POST-LAUNCH MILESTONES (phase-gated)

---

### TASK PL.1 — dsd health deep (gate: health in daily use)

**Prompt for Claude Code:**
```
Create internal/collectors/cpu_detail.go:
  Name: "CPUDetail", Timeout: 2s
  Per-core data from:
  - /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq  (frequency)
  - /sys/bus/platform/drivers/coretemp/*/hwmon/*/temp*_input (temperature milli-celsius)
  - Throttle: compare current freq vs max freq from scaling_max_freq
  Return []models.CPUCoreInfo

Update cmd/health.go buildHealthDeepCollectors():
func buildHealthDeepCollectors(ctrCtx platform.ContainerContext) []collectors.Collector {
    base := buildHealthCollectors(ctrCtx)
    return append(base, collectors.NewCPUDetailCollector(ctrCtx))
}
Update healthDeepCmd RunE to use buildHealthDeepCollectors.
```

---

### TASK PL.2 — dsd docker (gate: GitHub issue requesting containers)

**Prompt for Claude Code:**
```
go get github.com/docker/docker/client

Create internal/collectors/docker.go:
  Name: "Docker", Timeout: 5s
  Auto-detect socket path:
    /var/run/docker.sock     → Docker
    /var/run/podman/podman.sock → Podman
  Use Docker Engine API v1.41
  Collect per container: ID (short), Name, Image, State, Status, RestartCount, Health
  Empty state (no socket found): return []models.ContainerInfo{} (not error)
  macOS Docker Desktop: /var/run/docker.sock also works

Create cmd/docker.go with:
  dsd docker command running DockerCollector
  Empty state message if no Docker/Podman socket found:
    ℹ️  No container runtime detected.
        → Install Docker: https://docs.docker.com/get-docker/
        → Or ensure Docker daemon is running: systemctl start docker
```

---

### TASK PL.3 — dsd k8s (gate: GitHub issue requesting Kubernetes)

**Prompt for Claude Code:**
```
go get k8s.io/client-go@latest
go get k8s.io/api@latest
go get k8s.io/apimachinery@latest

Create internal/collectors/k8s.go:
  Name: "Kubernetes", Timeout: 10s
  
  Kubeconfig detection order:
  1. In-cluster: rest.InClusterConfig()
  2. $KUBECONFIG env var
  3. ~/.kube/config
  
  Collect 8 failure modes (full spec in SPEC.md §models K8sInfo):
  1. OOMKilled: lastTerminationState.terminated.reason == "OOMKilled"
  2. Evicted:   pod.Status.Reason == "Evicted"
  3. CrashLoop: state.waiting.reason contains "CrashLoop"
  4. ImagePull: state.waiting.reason contains "ImagePull" or "ErrImagePull"
  5. Pending:   Phase == Pending, read PodScheduled condition message
  6. PVC:       PVC.Status.Phase != Bound
  7. CoreDNS:   pods label k8s-app=kube-dns, count Ready vs Total
  8. Nodes:     conditions MemoryPressure, DiskPressure, PIDPressure

  Empty state (no kubeconfig):
    ℹ️  No kubeconfig found.
        → Set KUBECONFIG=/path/to/your/config
        → Or copy kubeconfig to ~/.kube/config

Create cmd/k8s.go:
  dsd k8s      → K8sCollector
  dsd k8s deep → K8sCollector (same for now — BestEffort/throttling added when gate met)
```

---

## MILESTONE TRACKER

| Task | Description | Status |
|---|---|---|
| 0.1–0.7 | Scaffold through tips engine | ✅ Done |
| 0.8 | Baseline system | ⬜ Todo |
| 0.9 | Config layer | ⬜ Todo |
| 0.10 | 12 collectors | ⬜ Todo |
| 0.11 | Render layer | ⬜ Todo |
| 0.12 | TUI components | ⬜ Todo |
| 0.13 | Wire cmd/health.go | ⬜ Todo |
| 1.1 | --diff + --since-deploy | ⬜ Todo |
| 1.2 | --post-mortem + --story | ⬜ Todo |
| 1.3 | --qr + Pro labels | ⬜ Todo |
| 1.4 | Milestones wiring | ⬜ Todo |
| 2.1 | dsd examples + dsd init | ⬜ Todo |
| 2.2 | dsd hook install | ⬜ Todo |
| 3.1 | dsd net + dsd services | ⬜ Todo |
| 3.2 | dsd net deep | ⬜ Todo |
| 3.3 | CI verification | ⬜ Todo |
| 3.4 | Phase 1 commit | ⬜ Todo |
| 4.1 | --watch mode | ⬜ Todo |
| 4.2 | --yaml output | ⬜ Todo |
| 4.3 | Final integration | ⬜ Todo |
| PL.1 | dsd health deep | ⬜ Gated |
| PL.2 | dsd docker | ⬜ Gated |
| PL.3 | dsd k8s | ⬜ Gated |

---

*DashDiag Implementation Plan — paired with SPEC.md v48.0*
