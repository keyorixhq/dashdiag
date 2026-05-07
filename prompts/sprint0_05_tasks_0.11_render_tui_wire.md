# DashDiag — Sprint 0: Tasks 0.11 + 0.12 + 0.13
## Render layer + TUI + cmd/health.go wiring
## Paste each block into Claude Code separately

---

## TASK 0.11 — Render layer

Paste this into Claude Code:

```
Create the complete render layer. 7 files.

RULE: All lipgloss styles in internal/render/styles.go ONLY.
RULE: Always AdaptiveColor — never hardcoded hex.
RULE: All progress to stderr. All output to stdout.

---

FILE 1: internal/render/styles.go

package render

import "github.com/charmbracelet/lipgloss"

var (
    StyleOK   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light:"#2E7D32", Dark:"#66BB6A"})
    StyleWarn = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light:"#E65100", Dark:"#FFB74D"})
    StyleCrit = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light:"#B71C1C", Dark:"#EF5350"})
    StyleInfo = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light:"#1565C0", Dark:"#64B5F6"})
    StyleDim  = lipgloss.NewStyle().Faint(true)
    StyleBold = lipgloss.NewStyle().Bold(true)
    StyleBox  = lipgloss.NewStyle().
                    Border(lipgloss.NormalBorder()).
                    BorderForeground(lipgloss.AdaptiveColor{Light:"#BDBDBD", Dark:"#424242"}).
                    Padding(0, 1)
)

func styleForStatus(status string) lipgloss.Style {
    switch status {
    case "CRIT": return StyleCrit
    case "WARN": return StyleWarn
    case "INFO": return StyleInfo
    default:     return StyleOK
    }
}

---

FILE 2: internal/render/health.go

type Renderer struct { mode output.OutputMode }
func NewRenderer(mode output.OutputMode) *Renderer

func (r *Renderer) PrintAll(results []runner.Result, insights []models.Insight)
// Format: one padded line per check
// Human:  "CPU        ✅  load 0.52 / 4 cores (13%)"
// Plain:  "CPU        OK  load 0.52 / 4 cores (13%)"
// For each result: find matching insight, use its Message as value
// Status icon: output.StatusIcon(status, r.mode)
// Column width: check name left-padded to 12 chars

func (r *Renderer) PrintSummary(insights []models.Insight) int
// Returns exit code: 0=OK, 1=WARN, 2=CRIT
// Print separator line then summary:
// Human:  "⚠️  1 warning — Memory: 14.2G / 16G used (88%)"
//         "   → ps aux --sort=-%mem | head -10"
// Plain:  "WARN: Memory: 14.2G / 16G used (88%)"
// JSON:   (no summary, return exit code only)
// Traverse insights: CRIT=2, WARN=1, else 0

func (r *Renderer) PrintContainerBanner(ctx platform.ContainerContext)
// "ℹ️  Running inside a container — showing container limits"
// Only in ModeHuman

---

FILE 3: internal/render/diff.go

From SPEC.md --diff spec:
### Priority 1 — `--diff` : What changed since last run
**Build in:** Phase 1 (renderer only, 1 day)
**Viral mechanic:** Comparison virality — engineers share diffs in incident Slack threads
**Revenue path:** Local diff is free → cloud baseline history is paid (Team tier)

```bash
# Baseline saved automatically after every run to ~/.dsd/baselines/<hostname>-latest.json
dsd health --diff

# Output:
⚡ Changes since last run (2h 14m ago) — web-prod-01

  Memory:   82% → 94%   ⚠️  +12% and growing
  Systemd:  0 failed → 1 failed  ❌  nginx.service added
  FD count: 4,821 → 48,210  ⚠️  10x spike

  Unchanged (9 checks): CPU ✅  Disk ✅  Network ✅  Clock ✅  ...

→ Something changed 2 hours ago — run dsd health deep for full picture
```

**Implementation:**
```go
// internal/baseline/baseline.go
// Save after every run:
//   ~/.dsd/baselines/<hostname>-latest.json   ← current run
//   ~/.dsd/baselines/<hostname>-prev.json     ← previous run (rotated)
// --diff loads prev.json, compares field by field, renders only changed fields
// Fields that changed WARN→CRIT render red; OK→WARN render yellow; CRIT→OK render green
// Unchanged fields collapsed to one summary line

// stdin piping — accept baseline from stdin with:
//   dsd health --diff -          (dash = read from stdin)
//   cat yesterday.json | dsd health --diff -
//   aws s3 cp s3://my-bucket/baseline.json - | dsd health --diff -
//
// This makes --diff scriptable: engineers can store baselines in S3, git,
// or any remote store and compare against them without manual file management.
//
// Detection:
func loadBaseline(path string) (*models.Snapshot, error) {
    if path == "-" {
        // Read from stdin
        data, err := io.ReadAll(os.Stdin)
        if err != nil { return nil, err }
        return parseSnapshot(data)
    }
    if path != "" {
        // Explicit file path
        data, err := os.ReadFile(path)
        if err != nil { return nil, err }
        return parseSnapshot(data)
    }
    // Default: load from ~/.dsd/baselines/<hostname>-prev.json
    return loadPrevBaseline()
}
```

**Why this is Priority 1:** One day to build. No backend. Direct conversion question:
"Can I see last week's baseline?" = paying customer asking to hand over money.

---

### Priority 1b — `--since-deploy` : What changed since the last deploy (half a day)
**Build in:** Phase 1 alongside `--diff` (shares all baseline infrastructure)

func PrintDiff(before, after *baseline.Snapshot, mode output.OutputMode) error
// Human output format:
//   ⚡ Changes since last run (2h 14m ago) — hostname
//
//     Memory:   82% → 94%   ⚠️  +12% and growing
//     Systemd:  0 failed → 1 failed  ❌  nginx.service added
//
//     Unchanged (9 checks): CPU ✅  Disk ✅  Network ✅  ...
//
//   → Something changed — run: dsd health deep
//
// Rules:
// - Call baseline.ComputeDiff to get []DiffEntry
// - Show CHANGED entries first (Improved last among changed)
// - Collapse unchanged into one summary line
// - Time ago: "47 min ago" / "2h 14m ago" / "3 days ago"
// - Plain: ASCII arrows (->) no colour
// - JSON: output raw []DiffEntry as JSON

---

FILE 4: internal/render/postmortem.go

From SPEC.md --post-mortem spec:
### Priority 3 — `--post-mortem` : Populated incident template
**Build in:** Phase 1 (renderer only, 1 day)
**Viral mechanic:** Team virality — post-mortems reviewed by entire engineering teams
**Revenue path:** Free template → paid history ("show all incidents last 90 days")

```bash
dsd health --post-mortem "API latency spike 14:30-15:15"

# Output (markdown, paste into Notion/Confluence/GitHub/Linear):
#### Incident: API latency spike 14:30-15:15
**Server:** web-prod-01  |  **Captured:** 2026-04-15 15:22 UTC  |  **By:** dsd v1.2.3

#### System State at Time of Capture
| Check | Status | Value | Threshold |
|---|---|---|---|
| CPU | ⚠️ WARN | load 3.8/4 cores (95%) | > 70% |
| Memory | ❌ CRIT | 312MB free / 16GB (98%) | > 95% |
| Disk IO | ❌ CRIT | sda 97% util, 180ms await | > 85% |
| Systemd | ✅ OK | 0 failed units | — |
| Network | ✅ OK | gateway 2ms, DNS 12ms | — |

#### Heuristic Analysis
- Memory pressure (98%) + active swap thrashing (si=142, so=89/sec) → OOM risk
- IO saturation on sda (97%, 180ms) → 3 processes in D-state
- Likely sequence: memory consumer → swap → IO saturation → hung processes

#### Recommended Investigation Steps
1. `ps aux --sort=-%mem | head -10` — identify top memory consumers
2. `iostat -x 1 5` — confirm IO device and utilization
3. `lsof +L1` — check for deleted-but-open files consuming disk
4. `journalctl -p err --since "2 hours ago"` — check for error patterns

#### Timeline
<!-- Paste: dsd health --diff output here -->

#### Resolution
<!-- Fill in -->

---
*Generated by DashDiag v1.2.3 — https://dashdiag.sh*
```

**Implementation:**
```go
// internal/render/postmortem.go
// --post-mortem "title" activates ModePostMortem in DetectMode()
// Renders full markdown document with:
//   - timestamped header
//   - check results table (all checks, not just failing)
//   - heuristics analysis section (from insights engine)
//   - investigation steps (from hints in each insight)
//   - empty resolution section for engineer to fill
// Automatically uses --out if specified, else stdout
// Footer: "Generated by DashDiag" — brand impression on every post-mortem
```

---

### Priority 4 — `--badge` : GitHub README status badge
**Build in:** Phase 2 (requires dashdiag.sh backend, 3 days + infra)
**Viral mechanic:** Passive virality — badge on popular repos = thousands of impressions
**Revenue path:** Badge account (free) → team dashboard (paid)

```bash
dsd health --badge
# → Badge URL generated: https://img.shields.io/endpoint?url=https://snap.dashdiag.sh/badge/abc123
# → Add to README.md:
#   ![Server Health](https://img.shields.io/endpoint?url=https://snap.dashdiag.sh/badge/abc123)
# → Update badge: add to cron:
#   */5 * * * * dsd health --json | curl -sX POST https://snap.dashdiag.sh/badge/abc123/update -d @-
```

Badge states:
```
[dsd: healthy]     — green   — all checks passed
[dsd: 2 warnings]  — yellow  — WARN checks present
[dsd: 1 critical]  — red     — CRIT checks present
[dsd: stale]       — grey    — not updated in > 10 minutes
```

**Implementation:** shields.io custom endpoint format — DashDiag serves a JSON endpoint
that shields.io polls. Engineer registers a badge token (free dashdiag.sh account),
pushes updates via `--badge`. Backend is a simple key-value store (Redis + tiny API).

---

### Priority 5b — `--report --weekly` / `--report --monthly` : Usage Summary Report (1 day)

Reads entirely from `~/.dsd/state.json` — no collectors, no network, no backend.
Available after one week of runs. Surfaces value the engineer already created but
cannot see. The upgrade prompt is the natural conversion moment.

```bash
$ dsd report --weekly

╔═══════════════════════════════════════════╗
║   DashDiag Weekly Report — web-prod-01    ║
║   Week of Apr 14–20, 2026                 ║
╠═══════════════════════════════════════════╣
║ Checks run:       47   (6.7 / day avg)    ║
║ Issues detected:  12   (8 WARN, 4 CRIT)   ║
║ Most frequent:    Memory WARN  × 8        ║
║ Cleanest day:     Tuesday — all clear     ║
║ Commands used:    health × 40, net × 7   ║
║ Time saved:       ~47 minutes             ║
╚═══════════════════════════════════════════╝

💡 Memory is your most common issue — try: dsd health --diff
   See 90-day history + trends: dashdiag.sh/teams  (Team plan)
```

```bash
$ dsd report --monthly --out april-2026.md
# Saves markdown version for runbooks / retrospectives
```

**Implementation:**
```go
// internal/render/weekly.go
// WeeklyReport reads state.json fields:
//   - total_runs, command_counts   → activity summary
//   - error_exits, shown_milestones → issue frequency
//   - current_streak, last_run_date → consistency

func RenderPostMortem(title string, snap *baseline.Snapshot, insights []models.Insight, mode output.OutputMode) string
// Always markdown output regardless of mode
// Template:
//   #### Incident: <title>
//   **Server:** hostname  |  **Captured:** RFC3339  |  **By:** dsd vX.Y.Z
//
//   #### System State at Time of Capture
//   | Check | Status | Value | Threshold |
//   |---|---|---|---|
//   (all checks — OK and WARN and CRIT)
//
//   #### Issues Detected
//   - ❌ CRIT check: message
//     → hint command 1
//   - ⚠️ WARN check: message
//
//   #### Recommended Investigation Steps
//   (numbered, deduplicated hints from all insights)
//
//   #### Timeline
//   <!-- Paste: dsd health --diff output here -->
//
//   #### Resolution
//   <!-- Fill in -->
//
//   ---
//   *Generated by DashDiag vX.Y.Z — https://dashdiag.sh*

---

FILE 5: internal/render/story.go

From SPEC.md --story spec:
### Priority 2 — `--story` : Human-readable system narrative
**Build in:** Phase 1 (renderer only, 2 days)
**Viral mechanic:** Paste virality — engineers paste narratives into post-mortems and Slack
**Revenue path:** Free forever — drives installs through post-mortem sharing

```bash
dsd health --story

# Output:
📋 System narrative — web-prod-01 — 2026-04-15 14:32 UTC

The server is under memory pressure. Available RAM has dropped to 312MB (98% used)
and swap is actively thrashing at 142 pages/sec in, 89 pages/sec out — a pattern
that typically precedes OOM kills within minutes.

Disk IO on sda is saturated at 97% utilization with 180ms await — 9x above the
healthy SSD threshold. Three processes are in uninterruptible D-state sleep,
consistent with IO blocking caused by the disk saturation.

Network, clock, and systemd units are healthy. 9 of 12 checks passed.

Most likely sequence: memory consumer → swap thrashing → IO saturation → hung processes.
Immediate action: ps aux --sort=-%mem | head -10
```

**Implementation:**
```go
// internal/render/story.go
// Pure deterministic template rendering — no LLM, no API call.
// Input: []models.Insight from heuristics engine
// Templates:
//   "memory_pressure" → paragraph about RAM + swap + OOM risk
//   "io_saturation"   → paragraph about disk util + await + D-state correlation
//   "cpu_saturated"   → paragraph about load + cores + process count
//   "network_fault"   → paragraph about interface + gateway + routing
// Severity ordering: CRIT items appear first, WARN items second
// All-healthy template: one sentence — "All 12 checks passed. System healthy."
// --story does NOT use AI — this distinction must be clear in docs and output footer
```

**Note on UnpackOps boundary:** `--story` is deterministic template rendering.
UnpackOps/`--ai` does probabilistic root cause inference. They are different products.
`--story` says "memory is high and swap is thrashing." UnpackOps says "this is probably
a Node.js heap leak in your request handler." Keep that line clear.

---

### Priority 3 — `--post-mortem` : Populated incident template
**Build in:** Phase 1 (renderer only, 1 day)
**Viral mechanic:** Team virality — post-mortems reviewed by entire engineering teams

func RenderStory(insights []models.Insight, snap *baseline.Snapshot) string
// 100% deterministic — NO AI — template-based
// One paragraph per active failure pattern:
//
// "memory_pressure" (WARN/CRIT memory):
//   "Memory pressure detected on <hostname>. Used: <pct>% of <total>GB.
//    Swap activity: <rate>/sec. Risk of OOM kill if trend continues.
//    Top consumers: run ps aux --sort=-%mem | head -10"
//
// "io_saturation" (WARN/CRIT IO):
//   "Disk IO saturation on <hostname>. Device <dev> at <util>% utilisation
//    with <await>ms average await. <N> processes in D-state (uninterruptible IO wait)."
//
// "cpu_saturated" (WARN/CRIT CPU):
//   "CPU load elevated: <load1> across <n> cores (<pct>% of capacity).
//    System has been under sustained load for the past 5 and 15 minute windows."
//
// "network_fault" (WARN/CRIT network):
//   "Network connectivity issue detected. Gateway ping: <ms>ms. <N> CLOSE_WAIT
//    connections indicate a connection leak or upstream service problem."
//
// "all_healthy" (no WARN or CRIT):
//   "All 12 health checks passed on <hostname>. System is operating normally."
//
// Combine applicable paragraphs with blank lines between.

---

FILE 6: internal/render/json.go

func RenderJSON(results []runner.Result, insights []models.Insight) ([]byte, error)
// Build a struct with: hostname, timestamp, version, checks[], insights[]
// json.MarshalIndent — 2 space indent
// This is the public JSON contract — schema must be stable

---

FILE 7: internal/render/weekly.go

func RenderWeekly(state *tips.State, period string) string
// Guard: state.TotalRuns < 7 → return info message
// Format terminal box:
//   ╔═══════════════════════════════════════════╗
//   ║   DashDiag Weekly Report — <hostname>     ║
//   ╠═══════════════════════════════════════════╣
//   ║ Checks run:       47   (6.7 / day avg)    ║
//   ║ Time saved:       ~47 minutes             ║
//   ╚═══════════════════════════════════════════╝
//   💡 See 90-day history: dashdiag.sh/teams
//
// Data from state.TotalRuns, state.CommandCounts, state.ErrorExits
// TimeSaved: TotalRuns * 1 (one minute per manual check)

Golden file tests:
  go test ./internal/render/... -update  (first run to generate)
  go test ./internal/render/... -v -race (verify)
```

---

## TASK 0.12 — TUI components
### No SPEC.md needed

Paste this into Claude Code:

```
Create internal/tui/tui.go and internal/tui/select.go.
Used ONLY by dsd init and dsd hook install — nowhere else in the codebase.

FILE 1: internal/tui/tui.go

package tui

import "os"

func IsTTY() bool {
    fi, err := os.Stdin.Stat()
    if err != nil { return false }
    return (fi.Mode() & os.ModeCharDevice) != 0
}

FILE 2: internal/tui/select.go

Implement two reusable bubbletea components.
When IsTTY() returns false, fall back to numbered text prompts (no bubbletea).

SingleSelect:
  type SingleSelectModel struct {
      title   string
      options []string
      cursor  int
      chosen  string
      done    bool
  }
  func RunSingleSelect(title string, options []string) (string, error)
  // Returns the chosen option string
  // bubbletea when TTY, numbered prompt when not:
  //   1) Option A
  //   2) Option B
  //   Enter number (1-N):

MultiSelect:
  type MultiSelectModel struct {
      title    string
      options  []string
      selected []bool
      cursor   int
      done     bool
  }
  func RunMultiSelect(title string, options []string) ([]string, error)
  // Returns slice of chosen option strings
  // bubbletea: spacebar to toggle, enter to confirm
  // non-TTY: "Enter numbers separated by commas (e.g. 1,3,5):"

Both handle context cancellation (Ctrl+C returns empty, nil error).
```

---

## TASK 0.13 — Wire cmd/health.go
### No SPEC.md needed — implementation plan has complete code

Paste this into Claude Code:

```
Create cmd/dsd/main.go if not already present:
  package main
  import "github.com/keyorixhq/dashdiag/cmd"
  func main() { cmd.Execute() }

Create cmd/health.go — WIRING ONLY, maximum 80 lines:

package cmd

import (
    "context"
    "fmt"
    "os"
    "time"
    "github.com/spf13/cobra"
    "github.com/keyorixhq/dashdiag/internal/analysis"
    "github.com/keyorixhq/dashdiag/internal/baseline"
    "github.com/keyorixhq/dashdiag/internal/collectors"
    "github.com/keyorixhq/dashdiag/internal/config"
    "github.com/keyorixhq/dashdiag/internal/output"
    "github.com/keyorixhq/dashdiag/internal/platform"
    "github.com/keyorixhq/dashdiag/internal/render"
    "github.com/keyorixhq/dashdiag/internal/runner"
    "github.com/keyorixhq/dashdiag/internal/tips"
    "github.com/keyorixhq/dashdiag/internal/version"
)

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
    RunE:  runHealth,
}

func runHealth(cmd *cobra.Command, args []string) error {
    ctx := context.Background()
    plain, _   := cmd.Flags().GetBool("plain")
    jsonOut, _ := cmd.Flags().GetBool("json")
    outputFmt  := ""
    if jsonOut { outputFmt = "json" }
    mode := output.DetectMode(plain, false, outputFmt)

    ctrCtx  := platform.DetectContainerContext()
    cloudEnv := platform.DetectCloudEnvironment()
    cfg     := config.Default()

    // Re-engagement — BEFORE progress bar
    state, _ := tips.LoadState()
    if state != nil {
        tips.MaybePrintReengagement(state, mode, version.Version)
    }

    // Progress — prints estimate before any work starts
    cols := buildHealthCollectors(ctrCtx)
    p := output.NewCommandProgress("System health", 5*time.Second, mode, len(cols))
    p.Start()
    defer p.Done()

    // Run all collectors concurrently
    var results []runner.Result
    for r := range runner.RunAll(ctx, toRunnerCols(cols)) {
        p.Step(r.Name)
        results = append(results, r)
    }

    insights := analysis.ApplyThresholds(results, cfg, cloudEnv, ctrCtx)
    snap     := baseline.BuildSnapshot(results, insights)

    // Special flag handling (early returns)
    sdFlag, _  := cmd.Flags().GetBool("since-deploy")
    pmFlag, _  := cmd.Flags().GetString("post-mortem")
    if sdFlag { return baseline.RunSinceDeployDiff(mode) }
    if pmFlag != "" {
        fmt.Println(render.RenderPostMortem(pmFlag, snap, insights, mode))
        baseline.SaveBaseline(snap)
        return nil
    }

    // Render output
    renderer := render.NewRenderer(mode)
    if ctrCtx.InContainer { renderer.PrintContainerBanner(ctrCtx) }

    if mode == output.ModeJSON {
        data, err := render.RenderJSON(results, insights)
        if err == nil { os.Stdout.Write(data) }
    } else {
        renderer.PrintAll(results, insights)
    }

    // --diff overlay after main output
    diffFlag, _ := cmd.Flags().GetBool("diff")
    if diffFlag {
        prev, err := baseline.LoadBaseline("")
        if err == nil {
            render.PrintDiff(prev, snap, mode)
        } else {
            fmt.Fprintln(os.Stderr, "ℹ️  No previous baseline. Run dsd health again to enable --diff.")
        }
    }

    exitCode := renderer.PrintSummary(insights)
    baseline.SaveBaseline(snap)

    // Engagement features — AFTER all output
    if state != nil {
        tips.MaybePrintMilestone(state, mode)
        tips.MaybePrintTip(state, mode)
        state.TotalRuns++
        if state.CommandCounts == nil { state.CommandCounts = make(map[string]int) }
        state.CommandCounts["health"]++
        state.Save()
    }

    if exitCode > 0 { os.Exit(exitCode) }
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

func toRunnerCols(cols []collectors.Collector) []runner.Collector {
    out := make([]runner.Collector, len(cols))
    for i, c := range cols { out[i] = c }
    return out
}

After creating cmd/health.go, run:
  go build ./...
  make build
  ./dist/dsd health
  ./dist/dsd health --json | python3 -m json.tool
  ./dist/dsd health --plain
  echo $?
  ./dist/dsd healt

ALL must succeed. Fix any compilation errors before proceeding.
```

