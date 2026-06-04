# Flag consistency fixes

Eleven issues found across cmd/. Fix them in order. All changes are in cmd/ only —
no collectors, no models, no tests required (these are declaration/wiring fixes).

Read FLAG_DESIGN.md first for the full rationale.

---

## Fix 1 — Remove duplicate `--report` from root.go

**Problem:** `--report` is declared as a global persistent flag in `cmd/root.go` AND
as a local flag in `cmd/health.go`. Cobra silently uses the local one; the persistent
one is dead. The descriptions differ.

**File:** `cmd/root.go`

Remove this line:
```go
f.Bool("report", false, "generate full report")
```

`cmd/health.go` already has the correct local declaration with the right description.
No other command uses `--report`. Keep the health local declaration unchanged.

---

## Fix 2 — Remove local `--json` declarations from cis, tls, cve, timeline

**Problem:** These four commands declare `--json` locally, shadowing the global
persistent flag. They work, but `--help` shows `--json` in the local section with
four different description strings.

**Rule:** Only declare a flag locally if it needs a command-specific default or type.
`--json` is `Bool` with default `false` everywhere — use the global.

**Files:** `cmd/cis.go`, `cmd/tls.go`, `cmd/cve.go`, `cmd/timeline.go`

**cmd/cis.go** — remove:
```go
cisCmd.Flags().BoolVar(&cisJSON, "json", false, "output JSON")
```
Replace all uses of `cisJSON` with `cmd.Flags().GetBool("json")`.
Check where `cisJSON` is used and update those reads.
Also remove the `cisJSON bool` package-level variable declaration.

**cmd/tls.go** — remove:
```go
tlsCmd.Flags().Bool("json", false, "JSON output")
```
The existing read `jsonOut, _ := cmd.Flags().GetBool("json")` stays — it reads the
global flag correctly once the local shadow is gone.

**cmd/cve.go** — remove:
```go
cveCmd.Flags().Bool("json", false, "JSON output")
```
Same — the existing `GetBool("json")` read stays.

**cmd/timeline.go** — remove:
```go
timelineCmd.Flags().Bool("json", false, "output raw JSON (for dsd capture / scripting)")
```
The existing `GetBool("json")` read stays.

---

## Fix 3 — Remove local `--plain` from cpu.go

**Problem:** `cmd/cpu.go` declares `--plain` locally, shadowing the global.

**File:** `cmd/cpu.go`

Remove:
```go
cpuCmd.Flags().Bool("plain", false, "plain text output (no colour, machine-friendly)")
```

The existing `plain, _ := cmd.Flags().GetBool("plain")` read stays — it reads the
global flag correctly once the local shadow is gone.

---

## Fix 4 — Standardise --json and --plain descriptions in global flags

**Problem:** The global flag descriptions in `root.go` are terse. The local ones that
shadowed them had better descriptions. Now that the locals are removed, update the
global descriptions to be clear.

**File:** `cmd/root.go`

Replace:
```go
f.Bool("plain", false, "plain text output")
f.Bool("json", false, "JSON output")
```
with:
```go
f.Bool("plain", false, "plain text output (no colour, machine-friendly)")
f.Bool("json", false, "JSON output (machine-readable)")
```

---

## Fix 5 — cis: replace BoolVar/IntVar package-level vars with cmd.Flags().Get*

**Problem:** `cmd/cis.go` is the only command that uses package-level variables
(`cisJSON`, `cisPlain`, `cisLevel`, `cisFailOnly`, `cisStig`) bound via `BoolVar`/
`IntVar`. Every other command uses `cmd.Flags().GetBool()`. Inconsistent and harder
to test (global state).

**File:** `cmd/cis.go`

1. Remove all package-level variable declarations:
```go
var (
    cisLevel    int
    cisJSON     bool
    cisFailOnly bool
    cisPlain    bool
    cisStig     bool
)
```

2. Replace `BoolVar`/`IntVar` declarations in `init()` with standard `Bool`/`Int`:
```go
// Before:
cisCmd.Flags().IntVar(&cisLevel, "level", 1, "benchmark level (1 or 2)")
cisCmd.Flags().BoolVar(&cisJSON, "json", false, "output JSON")        // REMOVE — handled by Fix 2
cisCmd.Flags().BoolVar(&cisFailOnly, "fail-only", false, "show only FAIL results")
cisCmd.Flags().BoolVar(&cisPlain, "plain", false, "plain text output (no colour)")
cisCmd.Flags().BoolVar(&cisStig, "stig", false, "run DISA STIG checks instead of CIS")

// After:
cisCmd.Flags().Int("level", 1, "benchmark level (1 or 2)")
cisCmd.Flags().Bool("fail-only", false, "show only FAIL results")
cisCmd.Flags().Bool("stig", false, "run DISA STIG checks instead of CIS")
// --plain and --json: global, no local declaration needed (see Fix 2 and 3)
```

3. In `runCIS()` (or wherever these vars are read), replace each usage:
```go
// Before:
mode := output.DetectMode(cisPlain, false, "")
if cisJSON { ... }
if cisStig { ... }
if cisFailOnly { ... }
level := cisLevel

// After:
plain, _ := cmd.Flags().GetBool("plain")
jsonOut, _ := cmd.Flags().GetBool("json")
outputFmt := ""
if jsonOut { outputFmt = "json" }
mode := output.DetectMode(plain, false, outputFmt)
stig, _ := cmd.Flags().GetBool("stig")
failOnly, _ := cmd.Flags().GetBool("fail-only")
level, _ := cmd.Flags().GetInt("level")
```

After this fix, `dsd cis --json` will correctly use the global `--json` flag and
display JSON output (currently it uses a local shadow that works but is inconsistent).

---

## Fix 6 — Remove dead global flags from root.go

**Problem:** These flags are registered globally, accepted by every command, but
no command reads them. They pollute `--help` output and mislead users.

**Flags to remove from `cmd/root.go`:**
- `--compact` — nobody reads it
- `--debug` — only health reads it (move to health-local, see Fix 7)
- `--diff` — only health reads it (move to health-local)
- `--since-deploy` — only health reads it (move to health-local)
- `--story` — only health reads it (move to health-local)
- `--weekly` — only health reads it (move to health-local)
- `--yaml` — only health reads it (move to health-local)
- `--post-mortem` — only health reads it (String type, move to health-local)

**Keep in root.go (genuinely global or needed there):**
- `--json` ✅ every command reads it
- `--plain` ✅ every command reads it
- `--out` ✅ PersistentPreRun handles it for all commands
- `--watch` ✅ health + thermal + processes read it
- `--report` ❌ REMOVED in Fix 1 (health-local)
- `--share` keep hidden (future feature, not harmful)
- `--qr` keep hidden (health reads it)

---

## Fix 7 — Move health-only flags to health-local

**Flags that must move from root.go global to healthCmd.Flags() local:**
`debug`, `diff`, `since-deploy`, `story`, `weekly`, `yaml`, `post-mortem`

**File:** `cmd/health.go` — add to `init()`:
```go
healthCmd.Flags().Bool("debug", false, "enable debug logging")
healthCmd.Flags().Bool("diff", false, "show diff from previous run")
healthCmd.Flags().Bool("since-deploy", false, "show metrics since last deploy")
healthCmd.Flags().Bool("story", false, "human-readable narrative of current state")
healthCmd.Flags().Bool("weekly", false, "show weekly usage report")
healthCmd.Flags().Bool("yaml", false, "YAML output")
healthCmd.Flags().String("post-mortem", "", "generate post-mortem for given incident ID")
```

**Note:** `--debug`, `--yaml`, `--post-mortem`, `--diff`, `--since-deploy`, `--story`,
`--weekly` are already read in `runHealth()` via `cmd.Flags().GetBool()` /
`cmd.Flags().GetString()`. Since they're moving from persistent to local, the read
calls stay exactly the same — cobra reads local flags the same way.

**Verify:** `dsd disk --weekly` should now return an error ("unknown flag: --weekly")
instead of silently accepting it.

---

## Fix 8 — Suppress --out banner to stderr

**Problem:** When `--out file.txt` is used, the `⚡ DashDiag` banner still appears
on the terminal (it goes to stderr). This is correct behaviour but surprising.
When writing to a file, the intent is unattended/scripted — suppress the banner.

**File:** `cmd/root.go` — in `PersistentPreRun`:

```go
// Before:
PersistentPreRun: func(cmd *cobra.Command, args []string) {
    plain, _ := cmd.Flags().GetBool("plain")
    jsonOut, _ := cmd.Flags().GetBool("json")
    if !plain && !jsonOut {
        fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — %s\n", version.Version, platform.SystemLabel())
    }
    outPath, _ := cmd.Flags().GetString("out")
    if outPath != "" {
        ...
    }
},

// After — add outPath check to the banner condition:
PersistentPreRun: func(cmd *cobra.Command, args []string) {
    plain, _ := cmd.Flags().GetBool("plain")
    jsonOut, _ := cmd.Flags().GetBool("json")
    outPath, _ := cmd.Flags().GetString("out")
    if !plain && !jsonOut && outPath == "" {
        fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — %s\n", version.Version, platform.SystemLabel())
    }
    if outPath != "" {
        f, err := os.Create(outPath) // #nosec G304
        if err != nil {
            fmt.Fprintf(os.Stderr, "dsd: --out: %v\n", err)
            os.Exit(1)
        }
        os.Stdout = f
    }
},
```

---

## Fix 9 — watch-interval: document the different defaults in help text

**Problem:** `--watch-interval` defaults to 60s for health, 5s for thermal/processes.
Users see different defaults and don't know why.

**Files:** `cmd/thermal.go`, `cmd/processes.go`

Update the flag description to explain the default:
```go
// Before:
thermalCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode")
processesCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode")

// After:
thermalCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode (default 5s; health uses 60s)")
processesCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode (default 5s; health uses 60s)")
```

---

## Verification

```bash
# Build
go build ./...

# Tests — no logic changed, but confirm nothing broke
go test -race ./...

# Lint
golangci-lint run ./...

# Fix 1: --report not duplicated in health --help
./dist/dsd-darwin-arm64 health --help 2>&1 | grep -c "report"  # expect 1

# Fix 2+3: no local json/plain on cis/tls/cve/timeline/cpu
./dist/dsd-darwin-arm64 cis --help 2>&1 | grep "json"    # should show (from global inherited)
./dist/dsd-darwin-arm64 tls --help 2>&1 | grep "json"    # same
./dist/dsd-darwin-arm64 cpu --help 2>&1 | grep "plain"   # should show (from global)

# Fix 5: cis --json works
./dist/dsd-darwin-arm64 cis --json 2>/dev/null | python3 -m json.tool | head -3

# Fix 6+7: dead flags rejected by non-health commands
./dist/dsd-darwin-arm64 disk --weekly 2>&1 | grep -i "unknown flag"    # expect error
./dist/dsd-darwin-arm64 thermal --diff 2>&1 | grep -i "unknown flag"   # expect error
./dist/dsd-darwin-arm64 health --weekly 2>/dev/null | head -3           # still works

# Fix 8: --out suppresses stderr banner
./dist/dsd-darwin-arm64 thermal --out /tmp/thermal-test.txt 2>/dev/null
cat /tmp/thermal-test.txt | head -3  # output in file
rm /tmp/thermal-test.txt             # no banner in file

# Fix 8: --out with --json
./dist/dsd-darwin-arm64 thermal --json --out /tmp/thermal-json.json 2>/dev/null
python3 -m json.tool /tmp/thermal-json.json | head -3  # valid JSON
rm /tmp/thermal-json.json
```

---

## Commit message

```
fix(flags): resolve 9 flag consistency issues across cmd/

- root.go: remove duplicate --report (local in health.go takes precedence; 
  persistent was dead with wrong description)
- root.go: remove dead global flags — compact, debug, diff, since-deploy,
  story, weekly, yaml, post-mortem (only health reads them; now health-local)
- root.go: update --plain and --json descriptions to match previous local ones
- health.go: add debug/diff/since-deploy/story/weekly/yaml/post-mortem as
  local flags (moved from global; read calls unchanged)
- cis.go: remove local --json shadow + package-level BoolVar/IntVar vars;
  replace with cmd.Flags().GetBool/GetInt pattern matching all other commands
- tls.go, cve.go, timeline.go: remove local --json shadow (global flag used)
- cpu.go: remove local --plain shadow (global flag used)
- root.go PersistentPreRun: suppress stderr banner when --out is set
- thermal.go, processes.go: clarify --watch-interval help text re: different
  default vs health (60s vs 5s)
```
