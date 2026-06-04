# Flag unification — 6 small changes in one session

Six independent changes. Do them in order. Build and test after all six.
None of these touch any collector or model — all changes are in cmd/ only.

Read FLAG_DESIGN.md before starting to understand the full rationale.

---

## Change 1 — timeline: rename --hours to --since

**File:** `cmd/timeline.go`

`parseSinceDuration()` already exists in `cmd/logs.go` (same package) — use it directly.

In `init()`, replace:
```go
timelineCmd.Flags().Int("hours", 1, "how many hours back to look (1, 6, 24)")
```
with:
```go
timelineCmd.Flags().String("since", "1h", "how far back to look (e.g. 1h, 6h, 24h)")
```

In `runTimeline()`, replace:
```go
hours, _ := cmd.Flags().GetInt("hours")
```
with:
```go
sinceStr, _ := cmd.Flags().GetString("since")
since := parseSinceDuration(sinceStr)
hours := int(since.Hours())
if hours < 1 {
    hours = 1
}
```

Keep passing `hours` to `collectors.NewTimelineCollector(hours)` — the collector
signature doesn't change. The conversion from duration to hours is fine here because
the timeline collector operates in whole-hour windows.

The `--hours` flag is fully gone — no deprecation alias needed, it was never
documented externally and the session notes already refer to `--since`.

---

## Change 2 — k8s: wire --deep flag

**File:** `cmd/k8s.go`

`NewK8sDeepCollector()` already exists in `internal/collectors/k8s.go` and sets
`Deep: true`. It just needs to be wired to a flag.

In `init()`, add:
```go
k8sCmd.Flags().Bool("deep", false, "deep mode: OS-layer checks (kubelet, CNI, iptables, certs)")
```

In `runK8s()`, replace:
```go
for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewK8sCollector()}) {
```
with:
```go
deepFlag, _ := cmd.Flags().GetBool("deep")
col := collectors.Collector(collectors.NewK8sCollector())
if deepFlag {
    col = collectors.NewK8sDeepCollector()
}
for r := range runner.RunAll(ctx, []runner.Collector{col}) {
```

No other changes — the existing ModeJSON branch and printK8sReport already handle
both fast and deep output correctly.

---

## Change 3 — security: rename --suid to --deep

**File:** `cmd/security.go`

`--suid` is cryptic. `--deep` matches the convention everywhere else.
`--suid` stays as a hidden alias so existing scripts don't break.

In `init()`, replace:
```go
securityCmd.Flags().Bool("suid", false, "include SUID binary scan (slow on large filesystems)")
```
with:
```go
securityCmd.Flags().Bool("deep", false, "deep mode: include SUID binary scan (slow on large filesystems)")
securityCmd.Flags().Bool("suid", false, "alias for --deep (deprecated)")
_ = securityCmd.Flags().MarkHidden("suid")
```

In `runSecurity()`, replace:
```go
saveBaseline, _ := cmd.Flags().GetBool("save-baseline")
drift, _ := cmd.Flags().GetBool("drift")
if saveBaseline || drift {
    collectors.ScanSUIDBinaries(info)
}
```
with:
```go
saveBaseline, _ := cmd.Flags().GetBool("save-baseline")
drift, _ := cmd.Flags().GetBool("drift")
deepFlag, _ := cmd.Flags().GetBool("deep")
suidAlias, _ := cmd.Flags().GetBool("suid")
if saveBaseline || drift || deepFlag || suidAlias {
    collectors.ScanSUIDBinaries(info)
}
```

---

## Change 4 — --out via root.go PersistentPreRun

**File:** `cmd/root.go`

`--out` is already registered as a persistent flag but nobody reads it.
One change in `PersistentPreRun` makes it work for every command at once.

Replace the existing `PersistentPreRun`:
```go
PersistentPreRun: func(cmd *cobra.Command, args []string) {
    plain, _ := cmd.Flags().GetBool("plain")
    jsonOut, _ := cmd.Flags().GetBool("json")
    if !plain && !jsonOut {
        fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — %s\n", version.Version, platform.SystemLabel())
    }
},
```
with:
```go
PersistentPreRun: func(cmd *cobra.Command, args []string) {
    plain, _ := cmd.Flags().GetBool("plain")
    jsonOut, _ := cmd.Flags().GetBool("json")
    if !plain && !jsonOut {
        fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — %s\n", version.Version, platform.SystemLabel())
    }
    // --out: redirect stdout to file for any command
    outPath, _ := cmd.Flags().GetString("out")
    if outPath != "" {
        f, err := os.Create(outPath) // #nosec G304
        if err != nil {
            fmt.Fprintf(os.Stderr, "dsd: --out: %v\n", err)
            os.Exit(1)
        }
        // intentionally not closing f — process exits after command completes
        os.Stdout = f
    }
},
```

`os.Stdout = f` is the standard Go pattern for redirecting stdout globally.
The file handle leaks on normal exit (no `defer f.Close()`), which is correct —
closing stdout before the process exits can cause write errors on buffered output.

---

## Change 5 — --watch on thermal

**File:** `cmd/thermal.go`

Model the implementation exactly on `runWatch` in `cmd/health.go` — same
clear-screen pattern, same countdown ticker, same channel signalling.

Add to `init()`:
```go
thermalCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode")
```

In `runThermal()`, after `mode` is set and before the progress spinner, add:
```go
watchFlag, _ := cmd.Flags().GetBool("watch")
if watchFlag {
    interval, _ := cmd.Flags().GetDuration("watch-interval")
    return watchThermal(ctx, interval, mode)
}
```

Add the watch loop function:
```go
func watchThermal(ctx context.Context, interval time.Duration, mode output.OutputMode) error {
    run := func() {
        if mode == output.ModeHuman {
            fmt.Print("\033[H\033[2J") // clear screen
        }
        var result runner.Result
        for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewThermalCollector()}) {
            result = r
        }
        info, ok := result.Data.(*models.ThermalInfo)
        if !ok || info == nil {
            return
        }
        fmt.Printf("\n── %s ──\n", time.Now().Format("15:04:05"))
        printThermalReport(info, mode, 0)
    }

    run()
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return nil
        case <-ticker.C:
            run()
        }
    }
}
```

The `printThermalReport` call passes `elapsed=0` — the watch loop doesn't track
per-run elapsed time, it just refreshes. This is the same approach as `runWatch`
in health.go (passes `0` for elapsed in the watch path).

---

## Change 6 — --watch on processes

**File:** `cmd/processes.go`

Same pattern as Change 5.

Add to `init()`:
```go
processesCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode")
```

In `runProcesses()`, after `mode` is set and before the progress spinner, add:
```go
watchFlag, _ := cmd.Flags().GetBool("watch")
if watchFlag {
    interval, _ := cmd.Flags().GetDuration("watch-interval")
    return watchProcesses(ctx, interval, mode)
}
```

Add the watch loop function:
```go
func watchProcesses(ctx context.Context, interval time.Duration, mode output.OutputMode) error {
    run := func() {
        if mode == output.ModeHuman {
            fmt.Print("\033[H\033[2J") // clear screen
        }
        var procInfo *models.ProcessInfo
        for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewProcessesCollector()}) {
            if info, ok := r.Data.(*models.ProcessInfo); ok {
                procInfo = info
            }
        }
        if procInfo == nil {
            return
        }
        fmt.Printf("\n── %s ──\n", time.Now().Format("15:04:05"))
        printProcessesReport(ctx, procInfo, mode, 0)
    }

    run()
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return nil
        case <-ticker.C:
            run()
        }
    }
}
```

---

## Verification

```bash
# Build
go build ./...

# Tests — none of these changes touch any logic, only flag wiring
go test -race ./...

# Lint
golangci-lint run ./...

# Manual spot-checks on macOS:

# Change 1 — timeline --since
./dsd timeline --since 24h 2>/dev/null | head -3   # should show "last 24h"
./dsd timeline --since 1h  2>/dev/null | head -3   # should show "last 1h"
./dsd timeline --json --since 6h 2>/dev/null | python3 -m json.tool | grep window

# Change 2 — k8s --deep (macOS: no k8s so Detected=false, just verify flag is accepted)
./dsd k8s --deep 2>/dev/null | head -3

# Change 3 — security --deep
./dsd security --deep 2>/dev/null | head -3    # should run (no --suid error)
./dsd security --suid 2>/dev/null | head -3    # alias: should behave same as --deep

# Change 4 — --out
./dsd thermal --out /tmp/dsd-thermal-test.txt 2>/dev/null
cat /tmp/dsd-thermal-test.txt | head -3        # should contain thermal output
rm /tmp/dsd-thermal-test.txt

./dsd thermal --out /tmp/dsd-thermal-json.json --json 2>/dev/null
python3 -m json.tool /tmp/dsd-thermal-json.json | head -3   # valid JSON
rm /tmp/dsd-thermal-json.json

# Change 5 — thermal --watch (run for 6s, should show two refreshes, Ctrl+C)
# Manual only — can't automate interactive watch. Just verify flag is accepted:
timeout 6 ./dsd thermal --watch 2>/dev/null || true   # should show output, not error

# Change 6 — processes --watch (same)
timeout 6 ./dsd processes --watch 2>/dev/null || true

# Linux verification (deploy to PVE01 for --out and --deep on live collectors)
make release
scp dist/dsd-linux-amd64 root@192.168.10.20:/tmp/dsd
ssh root@192.168.10.20 '/tmp/dsd security --deep 2>/dev/null | grep -i suid'
ssh root@192.168.10.20 '/tmp/dsd thermal --out /tmp/thermal.txt 2>/dev/null && cat /tmp/thermal.txt | head -3'
```

---

## Commit message

```
feat(flags): timeline --since, k8s --deep, security --deep, --out, --watch on thermal+processes

- cmd/timeline.go: rename --hours → --since (duration string, e.g. "1h", "6h", "24h")
  reuses parseSinceDuration() from logs.go; NewTimelineCollector still takes int hours
- cmd/k8s.go: add --deep flag; wires NewK8sDeepCollector() (OS-layer checks)
- cmd/security.go: rename --suid → --deep; --suid kept as hidden alias (backward compat)
- cmd/root.go: --out now works for every command via PersistentPreRun stdout redirect
- cmd/thermal.go: --watch mode with 5s default interval; --watch-interval to override
- cmd/processes.go: --watch mode with 5s default interval; --watch-interval to override
```
