# DashDiag — Complete Implementation Plan
## Claude Code Execution Guide

**Version:** Based on DashDiag Project Bible v48.0  
**Goal:** Working binary shipping to first paying customer  
**Philosophy:** Build one layer at a time. Compile after every step. Commit when green.

---

## HOW TO USE THIS PLAN WITH CLAUDE CODE

Each task has:
- **Objective** — what must exist when done
- **Prompt** — paste this directly into Claude Code
- **Verify** — commands to run to confirm it worked
- **Commit** — the git commit message to use

Run `go build ./...` after every task. If it does not compile, do not move on.

---

## SPRINT 0 — FOUNDATION
### Goal: A binary that compiles, runs, and exits cleanly

---

### TASK 0.1 — Project scaffold and go.mod

**Objective:** Project compiles. `go build ./...` succeeds. `./dsd` prints version.

**Prompt for Claude Code:**
```
Create the complete Go project scaffold for DashDiag.

Module path: github.com/andreibeshkov/dashdiag
Go version: 1.22

Required files:

1. go.mod with these dependencies:
   github.com/spf13/cobra v1.8.1
   github.com/spf13/viper v1.18.2
   github.com/charmbracelet/lipgloss v0.10.0
   github.com/charmbracelet/bubbletea v0.25.0
   github.com/shirou/gopsutil/v3 v3.24.1
   gopkg.in/yaml.v3 v3.0.1
   github.com/skip2/go-qrcode v0.0.0-20231117125638-6ca3b78deaef
   github.com/prometheus-community/go-ping v0.4.0

2. cmd/dsd/main.go:
   package main
   import "github.com/andreibeshkov/dashdiag/cmd"
   func main() { cmd.Execute() }

3. cmd/root.go:
   - rootCmd: Use "dsd", Short "DashDiag — instant system health"
   - RunE calls runHealth (stub: just prints "dsd health — not yet implemented")
   - PersistentFlags: --plain (bool), --json (bool), --yaml (bool),
     --report (bool), --out (string), --debug (bool), --compact (bool),
     --diff (bool), --since-deploy (bool), --watch (bool),
     --post-mortem (string), --share (bool), --qr (bool)
   - SuggestionsMinimumDistance = 2
   - Version via ldflags
   - Execute() function

4. internal/version/version.go:
   var Version = "dev"
   var Commit  = "none"
   var Built   = "unknown"

5. Makefile with targets:
   - build: CGO_ENABLED=0 go build -ldflags with version injection -o dist/dsd ./cmd/dsd
   - check: go vet ./... && gofmt -l .
   - test:  go test -race -count=1 -timeout 60s ./...
   - clean: rm -rf dist/

6. .gitignore for Go (dist/, *.test, coverage.out, .DS_Store)

Every file must compile. Run go build ./... mentally before responding.
No placeholder TODO comments — real stubs only.
```

**Verify:**
```bash
go mod tidy
go build ./...
./dist/dsd --version   # should print "dsd version dev"
./dist/dsd healt       # should suggest "dsd health"
```

**Commit:** `chore: initial project scaffold with cobra root command`

---

### TASK 0.2 — Output layer (tty.go + progress.go)

**Objective:** OutputMode enum, DetectMode, StatusIcon, and CommandProgress all exist and are tested.

**Prompt for Claude Code:**
```
Create the output layer for DashDiag.

File 1: internal/output/tty.go

type OutputMode int
const (
    ModeHuman  OutputMode = iota
    ModePlain
    ModeReport
    ModeJSON
    ModeYAML
)

func DetectMode(plain, report bool, outputFmt string) OutputMode {
    switch {
    case outputFmt == "json":  return ModeJSON
    case outputFmt == "yaml":  return ModeYAML
    case outputFmt == "quiet": return ModePlain
    case report:               return ModeReport
    case plain:                return ModePlain
    case !isaTTY():            return ModePlain
    default:                   return ModeHuman
    }
}

func StatusIcon(status string, mode OutputMode) string {
    // Human mode: ✅ ⚠️  ❌ ℹ️  ⏳
    // Plain mode:  OK WARN FAIL INFO PENDING
    // Report mode: ✅ OK  ⚠️ WARN  ❌ FAIL  ℹ️ INFO
    // JSON/YAML:   (not called — handled by marshalling)
}

func isaTTY() bool // check os.Stderr is character device
func IsPlain(flag bool) bool // flag OR not a TTY

File 2: internal/output/progress.go

type CommandProgress struct {
    label    string
    estimate time.Duration
    mode     OutputMode
    total    int
    done     int
    start    time.Time
}

func NewCommandProgress(label string, estimate time.Duration, mode OutputMode, total int) *CommandProgress
func (p *CommandProgress) Start()                    // prints "⚡ label (read-only) — ~Xs" to stderr
func (p *CommandProgress) Step(collectorName string) // updates \r progress line on stderr
func (p *CommandProgress) Note(msg string)           // prints contextual note on new line
func (p *CommandProgress) Done()                     // clears line, prints elapsed time

Rules:
- ALL output to stderr — never stdout
- \r overwrite pattern for Step() in TTY mode
- In plain/non-TTY: static [INFO] lines
- No color in plain mode

File 3: internal/output/tty_test.go
Table-driven tests for DetectMode and StatusIcon.
All cases: all 5 modes, all status values, TTY and non-TTY.

File 4: internal/output/formatter.go
func ProLabel(tier string, mode OutputMode) string
  // Human: dim lipgloss "  ◆ Team" or "  ◆ Free account"
  // Plain: "  [Team]" or "  [Free account]"  
  // JSON/YAML: ""
```

**Verify:**
```bash
go build ./...
go test ./internal/output/... -v
```

**Commit:** `feat: add output layer — OutputMode, StatusIcon, CommandProgress`

---

### TASK 0.3 — All model structs

**Objective:** Every model defined in internal/models/ with JSON tags. JSON round-trip tests pass.

**Prompt for Claude Code:**
```
Create all model files for DashDiag. One struct per file.
Location: internal/models/

Rules:
- Every exported field has a json struct tag
- Status fields: string type, values "OK"|"WARN"|"CRIT"|"INFO"|"PENDING"
- StatusReason: string, human-readable
- NO methods, NO logic — pure data structs
- NO imports from internal packages — stdlib only

Files to create:

internal/models/cpu.go — CPUInfo:
  LoadAvg1, LoadAvg5, LoadAvg15 float64
  NumCPU int
  UsagePct float64
  LoadPct float64        // LoadAvg1 / NumCPU * 100
  Status, StatusReason string

internal/models/memory.go — MemoryInfo:
  TotalGB, FreeGB, UsedPct float64
  SlabMB float64           // kernel slab cache
  CommitLimitMB float64
  CommittedAsMB float64
  OverCommitted bool        // Committed_AS > CommitLimit
  Status, StatusReason string

internal/models/swap.go — SwapInfo:
  TotalGB, UsedGB, UsedPct float64
  PagesInPerSec float64    // si from /proc/vmstat delta
  PagesOutPerSec float64   // so from /proc/vmstat delta
  ZramDevices int
  ZramUsedPct float64
  Status, StatusReason string

internal/models/disk.go — DiskInfo:
  Filesystems []FilesystemInfo
  Status, StatusReason string

FilesystemInfo:
  Mount, Device, FSType string
  TotalGB, UsedGB, FreeGB float64
  UsedPct float64
  InodesUsedPct float64
  ReadOnly bool
  Status, StatusReason string

internal/models/io.go — IOInfo:
  Devices []IODeviceInfo
  Status, StatusReason string

IODeviceInfo:
  Name string
  IsSSD bool
  UtilPct float64
  AwaitMs float64
  ReadMBps, WriteMBps float64
  QueueDepth float64
  Status, StatusReason string

internal/models/network.go — NetworkInfo, InterfaceInfo:
  Interfaces []InterfaceInfo
  GatewayPingMs float64
  InternetPingMs float64
  DNSResolvesMs float64
  CloseWaitCount int
  NATDetected bool
  Status, StatusReason string

InterfaceInfo:
  Name, IP string
  Up bool
  RxDrops, TxDrops uint64
  SpeedMbps int

internal/models/clock.go — ClockInfo:
  Synced bool
  OffsetMs float64   // -1 if unavailable (macOS)
  Source string      // timedatectl / chronyc / systemsetup
  Status, StatusReason string

internal/models/fdlimits.go — FDInfo, FDProcessInfo:
  OpenCount, MaxCount uint64
  UsedPct float64
  HotProcesses []FDProcessInfo
  DeletedOpenFiles int
  DeletedOpenSizeGB float64
  Status, StatusReason string

FDProcessInfo:
  PID int
  Name string
  OpenFDs int
  SoftLimit int
  UsedPct float64

internal/models/process.go — ProcessState:
  PID, PPID int
  Name, State string
  CPU, MemMB float64
  WChan string

internal/models/systemd.go — SystemdInfo:
  Available bool
  FailedUnits []string
  StuckUnits []string
  Status, StatusReason string

internal/models/sysctl.go — SysctlInfo:
  VMSwappiness int
  NetSomaxconn int
  FSFileMax int
  KernelPIDMax int
  PIDCount int
  Status, StatusReason string

internal/models/mac_policy.go — MACPolicyInfo:
  SELinuxPresent bool
  SELinuxMode string
  SELinuxDenials int
  AppArmorPresent bool
  AppArmorMode string
  Status, StatusReason string

internal/models/logs.go — LogsInfo, LogError:
  ErrorCount, WarnCount int
  TopErrors []LogError
  Sources []string
  SinceMinutes int
  JournalSizeGB float64
  Status, StatusReason string

LogError:
  Message string
  Count int
  FirstSeen, LastSeen time.Time
  Source string

internal/models/security.go — SecurityInfo, PortEntry:
  FailedLogins int
  ListeningPorts []PortEntry
  SSHPermitRoot bool
  SSHPasswordAuth bool
  SudoNopasswd []string
  WorldWritableEtc []string
  Status, StatusReason string

PortEntry:
  Port int
  Protocol string
  Process string
  Expected bool

internal/models/insight.go — Insight:
  Level string    // CRIT, WARN, INFO
  Check string
  Message string
  Hints []string

Create internal/models/models_test.go with JSON round-trip tests for every struct.
Pattern: marshal to JSON, unmarshal back, compare key fields.
```

**Verify:**
```bash
go build ./...
go test ./internal/models/... -v
```

**Commit:** `feat: add all model structs with JSON round-trip tests`

---

### TASK 0.4 — Runner (concurrency engine)

**Objective:** Runner compiles. Streaming channel works. Tests prove fast collectors arrive before slow ones.

**Prompt for Claude Code:**
```
Create the runner package for DashDiag.

File: internal/runner/runner.go

type Collector interface {
    Name()    string
    Timeout() time.Duration
    Collect(ctx context.Context) (interface{}, error)
}

type Result struct {
    Name     string
    Data     interface{}
    Err      error
    Duration time.Duration
}

func RunAll(ctx context.Context, collectors []Collector) <-chan Result
  // - Runs all collectors concurrently in goroutines
  // - Each collector gets ctx derived from parent with collector.Timeout()
  // - Results stream through channel as they complete (not batched)
  // - Channel closes when all collectors done
  // - Never panics on collector error — wraps in Result{Err: err}
  // - Records actual Duration for --debug output

File: internal/runner/runner_test.go
Tests:
1. TestRunAll_AllComplete: 5 mock collectors (10ms, 50ms, 100ms, 200ms, 500ms)
   Verify all 5 results arrive, verify faster results arrive before slower
2. TestRunAll_CollectorError: one collector returns error
   Verify Result.Err is set, other collectors still complete
3. TestRunAll_ContextCancellation: cancel parent context mid-run
   Verify no goroutine leak (use goleak or manual WaitGroup check)
4. TestRunAll_Timeout: collector with 50ms timeout that sleeps 200ms
   Verify result arrives within ~100ms with context.DeadlineExceeded error

Mock collector pattern:
type mockCollector struct {
    name    string
    delay   time.Duration
    result  interface{}
    err     error
    timeout time.Duration
}
```

**Verify:**
```bash
go build ./...
go test ./internal/runner/... -v -race
```

**Commit:** `feat: add concurrent runner with streaming result channel`

---

### TASK 0.5 — Platform detection

**Objective:** Container and cloud environment detected correctly. Tests use fake paths.

**Prompt for Claude Code:**
```
Create the platform detection package.

File: internal/platform/container.go (no build tag — all platforms)

type ContainerContext struct {
    InContainer   bool
    IsDocker      bool
    IsPodman      bool
    IsKubernetes  bool
    CPULimitCores float64  // 0 = unlimited
    MemLimitMB    float64  // 0 = unlimited
    CgroupVersion int      // 1 or 2
}

func DetectContainerContext() ContainerContext
Detection logic:
  InContainer: /.dockerenv exists OR /run/.containerenv exists OR
               cgroup path contains "docker" or "kubepods"
  IsDocker: /.dockerenv exists
  IsPodman: /run/.containerenv exists
  IsKubernetes: KUBERNETES_SERVICE_HOST env var set
  CgroupVersion: /sys/fs/cgroup/cgroup.controllers exists → v2, else v1
  MemLimitMB (cgroup v2): read /sys/fs/cgroup/memory.max (parse "max" as 0)
  MemLimitMB (cgroup v1): read /sys/fs/cgroup/memory/memory.limit_in_bytes
  CPULimitCores (cgroup v2): read /sys/fs/cgroup/cpu.max (format: "quota period")

Make paths injectable for testing:
func detectContainerContextFromPaths(dockerenv, containerenv, cgroupV2 string) ContainerContext

File: internal/platform/cloud.go (no build tag)

type CloudEnvironment int
const (
    EnvUnknown      CloudEnvironment = iota
    EnvBareMetal
    EnvAWSEBS
    EnvAWSNVMe
    EnvGCP
    EnvAzure
    EnvDigitalOcean
)

func DetectCloudEnvironment() CloudEnvironment
Detection order (file reads first, network last):
  1. /sys/class/dmi/id/product_name → "Google Compute"→GCP, "Microsoft Azure"→Azure, "Amazon EC2"→detectAWSStorageType()
  2. /sys/class/dmi/id/bios_vendor  → "Amazon" → detectAWSStorageType()
  3. /sys/hypervisor/uuid           → starts with "ec2" → detectAWSStorageType()
  4. http://169.254.169.254 GET with 150ms timeout → detectAWSStorageType()
  5. Default: EnvBareMetal

func detectAWSStorageType() CloudEnvironment
  Read /sys/block/nvme*/device/model
  Contains "Instance Storage" → EnvAWSNVMe
  Otherwise → EnvAWSEBS

File: internal/platform/platform.go (all platforms)
func IsLinux() bool  { return runtime.GOOS == "linux" }
func IsMacOS() bool  { return runtime.GOOS == "darwin" }

File: internal/platform/container_test.go
Test DetectContainerContextFromPaths with temp directories containing
fake /.dockerenv, fake cgroup files (v1 and v2 formats).

File: internal/platform/cloud_test.go  
Test DetectCloudEnvironment with fake DMI files via temp directories.
Test the 150ms timeout: mock server that never responds.
```

**Verify:**
```bash
go build ./...
go test ./internal/platform/... -v -race
```

**Commit:** `feat: add platform detection for containers and cloud environments`

---

### TASK 0.6 — Analysis layer skeleton

**Objective:** Heuristics function exists, all thresholds from SPEC.md §12 implemented, table-driven tests for every boundary.

**Prompt for Claude Code:**
```
Create the analysis layer for DashDiag.

File: internal/analysis/thresholds.go

type Thresholds struct {
    // CPU
    CPULoadWarnMultiplier float64  // default 0.7
    CPULoadCritMultiplier float64  // default 0.9

    // Memory
    RAMWarnPct  float64  // default 80
    RAMCritPct  float64  // default 95
    SlabWarnPct float64  // default 20 (% of total RAM)

    // Disk
    DiskWarnPct  float64  // default 80
    DiskCritPct  float64  // default 90

    // Swap
    SwapWarnPct     float64  // default 20
    SwapCritPct     float64  // default 60
    SwapActivityWarn float64 // pages/sec > 0
    SwapActivityCrit float64 // pages/sec > 100

    // IO — cloud environment aware
    IOUtilWarnPctSSD   float64  // default 60 bare metal / 60 NVMe
    IOUtilCritPctSSD   float64  // default 85 bare metal / 85 NVMe
    IOAwaitWarnMsSSD   float64  // default 1ms bare metal / 5ms EBS / 5ms GCP
    IOAwaitCritMsSSD   float64  // default 5ms bare metal / 20ms EBS / 20ms GCP

    // NTP
    NTPOffsetWarnMs float64  // default 100
    NTPOffsetCritMs float64  // default 500

    // FD
    FDSystemWarnPct  float64  // default 80
    FDSystemCritPct  float64  // default 90
    FDProcWarnPct    float64  // default 80

    // Process
    ZombieWarnCount int  // default 5
    HungDStateCrit  int  // default 1

    // Systemd
    // FailedUnits: any = CRIT, StuckUnits: any = WARN

    // Logs
    JournalSizeWarnGB float64  // default 2
    JournalSizeCritGB float64  // default 5

    // SELinux
    SELinuxDenialsWarnPerHr int  // default 1
    SELinuxDenialsCritPerHr int  // default 10
}

func DefaultThresholds(env platform.CloudEnvironment) Thresholds
  // Adjusts IO thresholds based on cloud environment:
  // EnvAWSEBS, EnvGCP, EnvAzure: AwaitWarnMs=5, AwaitCritMs=20
  // EnvAWSNVMe, EnvBareMetal:    AwaitWarnMs=1, AwaitCritMs=5
  // EnvUnknown:                  AwaitWarnMs=2, AwaitCritMs=10

File: internal/analysis/heuristics.go

func ApplyThresholds(results []runner.Result, thresh Thresholds, env platform.CloudEnvironment) []models.Insight

For each result by type:
- models.CPUInfo   → check LoadPct vs CPULoadWarnMultiplier/CritMultiplier × NumCPU
- models.MemoryInfo → check UsedPct, SlabMB/Total, OverCommitted
- models.DiskInfo  → check each filesystem UsedPct and InodesUsedPct
- models.SwapInfo  → check UsedPct, PagesInPerSec, PagesOutPerSec
- models.IOInfo    → check each device UtilPct and AwaitMs (cloud-aware)
- models.NetworkInfo → check GatewayPingMs, DNSResolvesMs, CloseWaitCount
- models.ClockInfo → check Synced, OffsetMs
- models.FDInfo    → check UsedPct, HotProcesses, DeletedOpenSizeGB
- models.SystemdInfo → any FailedUnits = CRIT, StuckUnits = WARN
- models.SysctlInfo → NetSomaxconn < 1024 = WARN, < 512 = CRIT; PIDCount/PIDMax
- models.MACPolicyInfo → SELinuxDenials per hour vs thresholds

Each check produces an Insight with:
  Level: "WARN" or "CRIT"
  Check: the check name (e.g., "Memory", "Disk /var")
  Message: human-readable description of the problem
  Hints: 1-3 commands to run next

File: internal/analysis/heuristics_test.go
Table-driven tests for EVERY threshold boundary.
For each threshold test: below-warn, at-warn, above-warn, at-crit, above-crit.
Use mock runner.Result values — no real collectors needed.
```

**Verify:**
```bash
go build ./...
go test ./internal/analysis/... -v -race
```

**Commit:** `feat: add analysis layer with all thresholds and heuristics`

---

### TASK 0.7 — State management (tips, milestones, NPS)

**Objective:** state.json saves and loads atomically. Milestones fire at correct run counts.

**Prompt for Claude Code:**
```
Create the state management and tips system.

File: internal/tips/state.go

type State struct {
    TotalRuns       int            `json:"total_runs"`
    ShownMilestones []int          `json:"shown_milestones"`
    LastTipDate     string         `json:"last_tip_date"`
    TipIndex        int            `json:"tip_index"`
    TipsEnabled     bool           `json:"tips_enabled"`
    NPSDone         bool           `json:"nps_done"`
    NPSScore        string         `json:"nps_score"`
    NPSReason       string         `json:"nps_reason"`
    HookInstalled   bool           `json:"hook_installed"`
    CurrentStreak   int            `json:"current_streak"`
    LongestStreak   int            `json:"longest_streak"`
    LastRunDate     string         `json:"last_run_date"`
    LastVersion     string         `json:"last_version"`
    TrialOffered    bool           `json:"trial_offered"`
    PipedRuns       int            `json:"piped_runs"`
    CommandCounts   map[string]int `json:"command_counts"`
    ErrorExits      int            `json:"error_exits"`
}

func stateFilePath() string  // ~/.dsd/state.json
func LoadState() (*State, error)  // creates default if not exists, TipsEnabled=true
func (s *State) Save() error  // ATOMIC: write temp file then os.Rename

func (s *State) HasShownMilestone(m int) bool
func (s *State) MarkMilestone(m int)
func (s *State) HasShownStreak(days int) bool
func (s *State) MarkStreak(days int)
func (s *State) IncrementCommand(name string)

File: internal/tips/milestones.go

func MaybePrintMilestone(state *State, mode output.OutputMode)
  // 1. state.TotalRuns++
  // 2. Update streak (today vs yesterday vs older → increment/reset)
  // 3. Re-engagement: if gap >= 7 days AND ModeHuman → print "👋 Welcome back! N days"
  //    If version changed: "New in vX.Y.Z — run dsd --changelog"
  // 4. state.LastRunDate = today, state.LastVersion = version.Version
  // 5. Streak milestones: 7 days → "⚡ 7-day streak", 30 days → "🔥 30-day streak"  
  // 6. Run milestones: 10 (NPS), 50, 100, 500
  // 7. Pro trial: TotalRuns>=10 AND CurrentStreak>=5 AND !TrialOffered → offer
  // ONLY in ModeHuman and isaTTY()

func MaybeRunNPS(state *State, mode output.OutputMode)
  // Only at TotalRuns==10, !NPSDone, ModeHuman, isaTTY()
  // Print score question (0-10), read with fmt.Scanln
  // If score given: ask follow-up reason
  // Store in state, set NPSDone=true

func MaybePrintReengagement(state *State, mode output.OutputMode, ver string)
  // Call BEFORE health output (first thing printed)
  // Gap calculation and welcome back message

File: internal/tips/tips.go

var tips = []struct{ Message, Command, Tier string }{
    {"See only what changed since your last check", "dsd health --diff", ""},
    {"Get a human-readable narrative of system state", "dsd health --story", ""},
    {"Share a snapshot URL in Slack — no install needed", "dsd health --share", "Free account"},
    {"Generate a pre-filled post-mortem template", "dsd health --post-mortem \"title\"", ""},
    {"Deep network analysis: jitter, bonds, traceroute", "dsd net deep", ""},
    {"Markdown output for GitHub issues and Jira", "dsd health --report", ""},
    {"Compare health across multiple servers", "dsd compare server1 server2", "Team"},
    {"Auto-run dsd on SSH login or before deploys", "dsd hook install", ""},
    {"Monitor for changes every 60 seconds", "dsd health --watch", ""},
    {"Embed a live health badge in your README", "dsd health --badge", "Free account"},
    {"Custom thresholds and service checks", "~/.dsd.yaml", ""},
    {"Run all checks — the complete picture", "dsd full", ""},
}

func MaybePrintTip(state *State, mode output.OutputMode)
  // Only if TipsEnabled, ModeHuman, today != LastTipDate
  // Show AFTER health output
  // Format: "\n💡 Tip: <message>\n   Try: <command>\n   Tip N of 12  |  dsd tips (see all)  |  dsd config set tips off"
  // Pro tips add: "\n   ◆ <Tier>" at end
  // Update LastTipDate, TipIndex

func PrintAllTips() // dsd tips command — shows all 12

File: internal/tips/state_test.go
Tests:
- TestLoadState_Default: no file → creates with TipsEnabled=true
- TestSave_Atomic: verify temp file then rename (no partial writes)
- TestMilestoneFiresAtCorrectCount: mock state, verify milestone fires at 10, 50, 100
- TestStreakCalculation: test gap=0, gap=1, gap=2+ cases
- TestNPSFiresOnce: fires at run 10, not run 11
- TestReengagementAfterGap: gap < 7 = no message, gap >= 7 = message
```

**Verify:**
```bash
go build ./...
go test ./internal/tips/... -v -race
```

**Commit:** `feat: add state management, milestones, NPS survey, tip of the day`

---

### TASK 0.8 — Baseline system (--diff and --since-deploy)

**Objective:** Baselines save/load atomically. Diff computes correctly. Deploy time detected.

**Prompt for Claude Code:**
```
Create the baseline system for --diff and --since-deploy.

File: internal/baseline/baseline.go

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
    Raw    interface{} `json:"raw"`
}

type DiffEntry struct {
    Name         string
    Before       string  // status + value
    After        string
    StatusChange string  // "OK→WARN" etc
    Changed      bool
    Improved     bool    // CRIT→WARN or WARN→OK
}

func baselineDir() string   // ~/.dsd/baselines/
func latestPath(host string) string
func prevPath(host string) string

func SaveBaseline(snap *Snapshot) error
  // 1. Marshal to JSON
  // 2. Write to ~/.dsd/baselines/<host>-<timestamp>.json (atomic)
  // 3. Copy latest → prev
  // 4. Copy new → latest

func LoadBaseline(path string) (*Snapshot, error)
  // path == "-"  → read from os.Stdin
  // path != ""   → read from explicit file
  // path == ""   → load prev baseline

func LoadPrevBaseline(hostname string) (*Snapshot, error)

func ComputeDiff(before, after *Snapshot) []DiffEntry
  // Return ALL checks (Changed and Unchanged)
  // Changed = status differs OR value differs by >5%
  // Sort: CRIT changes first, WARN changes, improvements, unchanged

File: internal/baseline/since_deploy.go

func DetectLastDeployTime() (deployTime time.Time, signal string, err error)
  // Check in order, return first that succeeds:
  // 1. systemctl show nginx,apache2,caddy,postgres,mysqld,redis,docker,containerd
  //    --property=ActiveEnterTimestamp --value
  //    (try