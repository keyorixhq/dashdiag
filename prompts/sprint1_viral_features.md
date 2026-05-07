# DashDiag — Sprint 1 Implementation Prompts
## Tasks 1.1 through 1.4
## Paste each block into Claude Code

---

## TASK 1.1 + 1.2 — --diff, --since-deploy, --post-mortem, --story wiring

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

From SPEC.md --since-deploy spec:
### Priority 1b — `--since-deploy` : What changed since the last deploy (half a day)
**Build in:** Phase 1 alongside `--diff` (shares all baseline infrastructure)
**Viral mechanic:** Comparison virality — the post-deploy check engineers run every time
**Revenue path:** Same as `--diff` — local baselines free, cloud history paid

Zero engineer effort after one week of use. No config, no pipeline changes.
dsd auto-detects the last deploy time from service restart signals and finds
the nearest saved baseline from before that restart.

```bash
$ dsd health --since-deploy

⚡ Changes since last deploy (nginx restarted 47 min ago) — web-prod-01

  Memory:   61% → 78%   ⚠️  +17% since restart
  FD count: 4,821 → 12,440  ⚠️  growing after deploy
  IO util:  8% → 62%   ⚠️  elevated

  Unchanged (9 checks): CPU ✅  Disk ✅  Network ✅  Clock ✅  ...

→ Something changed when nginx restarted 47 min ago
```

**Implementation:**
```go
// internal/baseline/since_deploy.go

// DetectLastDeployTime finds the most recent service restart time.
// Checks multiple signals in order — uses whichever returns fastest.
func DetectLastDeployTime() (time.Time, string, error) {
    // Signal 1: systemd service ActiveEnterTimestamp (most accurate)
    // Check the most common services — first one found wins
    for _, svc := range []string{"nginx", "apache2", "caddy", "postgres",
        "mysql", "redis", "docker", "containerd"} {
        if t, err := systemdActiveEnter(svc); err == nil {
            return t, "systemd: " + svc + ".service restarted", nil
        }
    }

    // Signal 2: newest process start time from /proc/<pid>/stat
    // Finds the most recently started long-running process (uptime < 2h)
    if t, svc, err := newestProcessStart(2 * time.Hour); err == nil {
        return t, svc + " process started", nil
    }

    // Signal 3: newest Docker/container restart
    if t, name, err := newestContainerRestart(); err == nil {
        return t, "container " + name + " restarted", nil
    }

    // Signal 4: git log -1 (code deploy signal on dev/staging)
    if t, err := gitLastCommitTime(); err == nil {
        return t, "git: last commit pushed", nil
    }

    return time.Time{}, "", fmt.Errorf("no deploy signal detected")
}

// FindBaselineBeforeTime finds the newest baseline snapshot saved
// before the given time. Falls back to previous baseline if none found.
func FindBaselineBeforeTime(t time.Time, hostname string) (*models.Snapshot, error) {
    dir := filepath.Join(os.Getenv("HOME"), ".dsd", "baselines")
    entries, err := os.ReadDir(dir)
    if err != nil { return nil, err }

    var best *models.Snapshot
    var bestTime time.Time

    for _, e := range entries {
        if !strings.HasPrefix(e.Name(), hostname) { continue }
        info, _ := e.Info()
        if info.ModTime().Before(t) && info.ModTime().After(bestTime) {
            if snap, err := loadSnapshot(filepath.Join(dir, e.Name())); err == nil {
                best = snap
                bestTime = info.ModTime()
            }
        }
    }
    if best == nil {
        return nil, fmt.Errorf("no baseline found before %s", t.Format(time.RFC3339))
    }
    return best, nil
}

// Entry point — called when --since-deploy flag is set
func RunSinceDeployDiff(mode output.OutputMode) error {
    deployTime, signal, err := DetectLastDeployTime()
    if err != nil {
        // Graceful fallback — teach the engineer the habit
        fmt.Printf("ℹ️  No deploy signal detected.
")
        fmt.Printf("    Run dsd health before your next deploy to enable this check.
")
        fmt.Printf("    Or: dsd health --diff  to compare against your last run.
")
        return nil
    }

    hostname, _ := os.Hostname()
    baseline, err := FindBaselineBeforeTime(deployTime, hostname)
    if err != nil {
        // No pre-deploy baseline exists yet
        mins := int(time.Since(deployTime).Minutes())
        fmt.Printf("ℹ️  No pre-deploy baseline found (%s %d min ago).
", signal, mins)
        fmt.Printf("    Run dsd health before your next deploy to enable this check.
")
        fmt.Printf("    Or: dsd health --diff  to compare against your last run.
")
        return nil
    }

    // Run current health check and diff against pre-deploy baseline
    curr := runHealthSnapshot()
    mins := int(time.Since(deployTime).Minutes())
    fmt.Printf("⚡ Changes since last deploy (%s, %d min ago)

", signal, mins)
    return render.PrintDiff(baseline, curr, mode)
}
```

**Key design decisions:**
- Service restart detection uses systemd first (most accurate), falls back to
  `/proc` process start times (works everywhere), then container restarts, then git.
- Baseline matching uses file modification time on `~/.dsd/baselines/` —
  the baseline saved just before the deploy is automatically the right one.
- Both failure modes (no signal, no baseline) produce actionable messages that
  teach the habit. Neither produces an error exit — `--since-deploy` never blocks.
- After one week of running `dsd health` before deploys: works perfectly every time.
- Day 1 with no prior baselines: graceful message, no noise.

**Upgrade path:** "Can I see what changed across deploys this month?"
→ Team plan: 90-day baseline history, deploy timeline, trend charts.

---


Paste this into Claude Code:

```
Wire Sprint 1 viral flags into cmd/health.go.
Add --story and --weekly flags to cmd/root.go persistent flags:
  f.Bool("story", false, "human-readable narrative of current state")
  f.Bool("weekly", false, "show weekly usage report")

In runHealth(), add these checks AFTER insights are computed, BEFORE renderer.PrintAll():

  // --weekly: early return, reads state.json only (no collectors)
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

  // --story: deterministic narrative
  storyFlag, _ := cmd.Flags().GetBool("story")
  if storyFlag {
      fmt.Println(render.RenderStory(insights, snap))
      return nil
  }

Verify all flags work:
  ./dist/dsd health --diff
  ./dist/dsd health --since-deploy
  ./dist/dsd health --post-mortem "test incident"
  ./dist/dsd health --story
  ./dist/dsd health --weekly
```

---

## TASK 1.3 — --qr code + Pro labels in --help
### No SPEC.md needed

Paste this into Claude Code:

```
1. Create internal/output/qr.go:

package output

import (
    "fmt"
    "github.com/skip2/go-qrcode"
)

func PrintQRCode(url string, mode OutputMode) error {
    if url == "" { return nil }
    if mode == ModePlain || !isaTTY() {
        fmt.Println("Scan or visit: " + url)
        return nil
    }
    qr, err := qrcode.New(url, qrcode.Medium)
    if err != nil {
        fmt.Println("QR: " + url)
        return nil // non-fatal
    }
    fmt.Println(qr.ToString(false))
    fmt.Println(url)
    return nil
}

2. Add ProLabel to internal/output/formatter.go:

func ProLabel(tier string, mode OutputMode) string {
    switch mode {
    case ModeHuman:
        return StyleDim.Render("  ◆ " + tier)  // StyleDim from styles.go
    case ModePlain:
        return "  [" + tier + "]"
    default:
        return ""
    }
}

3. Update cmd/root.go Long description:
   rootCmd.Long = "DashDiag (dsd) — one command instant system health overview.

" +
       "◆ Team: dashdiag.sh/teams  |  ◆ Free account: dashdiag.sh/signup"

4. Wire --qr in runHealth() after --share URL is generated (stub shareURL="" for now):
   qrFlag, _ := cmd.Flags().GetBool("qr")
   if qrFlag {
       output.PrintQRCode(shareURL, mode) // shareURL="" until --share is implemented
   }

Verify:
  ./dist/dsd --help | grep "◆"
  go test ./internal/output/... -v -race
```

---

## TASK 1.4 — Milestones, NPS, and re-engagement wiring
### No SPEC.md needed — already in internal/tips/

Paste this into Claude Code:

```
Verify end-to-end that tips/milestones fire correctly.

1. Check internal/tips/state.go:
   - Save() uses atomic write (temp file + os.Rename) — if not, fix it
   - LoadState() creates default State with TipsEnabled:true if file not found

2. Check internal/tips/milestones.go:
   - MaybePrintMilestone fires at TotalRuns: 10 (NPS), 50, 100, 500
   - Streak updates correctly:
     if lastRunDate == yesterday → CurrentStreak++
     if lastRunDate == today    → no change (already ran today)
     else                       → CurrentStreak = 1 (broken or first)
   - MaybeShowReengagement: if lastRunDate gap >= 7 days → print welcome back
   - Pro trial: TotalRuns >= 10 AND CurrentStreak >= 5 AND !TrialOffered
     Print trial offer, set TrialOffered=true

3. Run end-to-end verification:
   go test ./internal/tips/... -v -race
   rm -f ~/.dsd/state.json
   for i in $(seq 1 10); do ./dist/dsd health 2>/dev/null; done
   cat ~/.dsd/state.json | python3 -m json.tool
   # total_runs should be 10, NPS should have fired on run 10

4. Commit Sprint 1:
   git add -A
   git commit -m "feat: Sprint 1 complete — viral features implemented"
   git tag v0.2.0-sprint1
```

