# V2 Security Drift Detection

## What this is

A new `dsd security --drift` mode that compares the current security state
against a saved baseline, reporting what changed. Specifically: new SUID
binaries, SSH config changes, new sudoers NOPASSWD entries, new cron jobs
writing to sensitive paths.

This is the last high-value V2 feature before the gap spec is fully closed.

Read these files completely before writing anything:
- `internal/collectors/security_linux.go` (1697 lines — all existing security checks)
- `internal/models/security.go` (162 lines — SecurityInfo struct, all fields)
- `internal/baseline/baseline.go` (180 lines — existing snapshot/diff infrastructure)
- `cmd/security.go` — existing `dsd security` command structure
- `internal/analysis/heuristics.go` — find `checkSecurity()` to understand how
  SecurityInfo maps to insights

The existing `internal/baseline/` works at the *health check level* — it stores
status strings ("OK", "WARN") for each check name. Security drift needs
*file-level content hashing* — a different store. Do NOT try to reuse the health
baseline for this. It belongs in a separate file.

---

## What to build

### Part 1 — Security baseline store (`internal/baseline/security_baseline.go`)

A new file in `internal/baseline/`. Completely separate from `baseline.go`.

```go
package baseline

// SecurityBaseline stores hashed snapshots of security-sensitive files and
// lists of security-sensitive artefacts (SUID binaries, sudoers entries).
// Saved to ~/.dsd/security-baseline.json.
// Updated explicitly with: dsd security --save-baseline
// Compared against with: dsd security --drift
type SecurityBaseline struct {
    SavedAt  time.Time         `json:"saved_at"`
    Hostname string            `json:"hostname"`
    // SSH config file hashes (path → sha256 hex of file content)
    SSHConfigHashes map[string]string `json:"ssh_config_hashes"`
    // Known SUID binary paths (the list as of baseline time)
    KnownSUIDs []string `json:"known_suids"`
    // Sudoers NOPASSWD entries as of baseline time
    SudoNopasswd []string `json:"sudo_nopasswd"`
    // Suspect cron entries as of baseline time
    SuspectCrons []string `json:"suspect_crons"`
}

// SecurityBaselinePath returns the path to the security baseline file.
// ~/.dsd/security-baseline.json
func SecurityBaselinePath() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".dsd", "security-baseline.json")
}

// SaveSecurityBaseline writes the baseline to disk atomically.
func SaveSecurityBaseline(b *SecurityBaseline) error

// LoadSecurityBaseline reads the baseline from disk.
// Returns nil, nil when no baseline exists yet.
func LoadSecurityBaseline() (*SecurityBaseline, error)

// BuildSecurityBaseline creates a baseline from a current SecurityInfo snapshot.
func BuildSecurityBaseline(info *models.SecurityInfo) *SecurityBaseline
```

For `SaveSecurityBaseline`: use the same atomic write pattern as `SaveBaseline`
in `baseline.go` (write to temp file, then `os.Rename`). The directory is
`~/.dsd/` — create it if it doesn't exist.

For `BuildSecurityBaseline`:
```go
func BuildSecurityBaseline(info *models.SecurityInfo) *SecurityBaseline {
    b := &SecurityBaseline{
        SavedAt:      time.Now(),
        Hostname:     hostname(),
        KnownSUIDs:   info.SUIDBinaries,
        SudoNopasswd: info.SudoNopasswd,
        SuspectCrons: info.SuspectCrons,
    }
    // Hash SSH config files
    b.SSHConfigHashes = hashSSHConfigFiles()
    return b
}
```

`hashSSHConfigFiles()` should hash:
- `/etc/ssh/sshd_config`
- All files matching `/etc/ssh/sshd_config.d/*.conf`
- Returns map[path]sha256hex. Files that don't exist are omitted.
SHA-256 using `crypto/sha256`. No external tools.

### Part 2 — SecurityDiff struct and comparison

Still in `internal/baseline/security_baseline.go`:

```go
// SecurityDiff holds what changed between a saved baseline and the current state.
type SecurityDiff struct {
    NewSUIDs      []string // SUID binaries not in the baseline
    RemovedSUIDs  []string // SUID binaries in baseline but now gone
    NewSudoEntries []string // new NOPASSWD entries since baseline
    NewCronEntries []string // new suspect cron entries since baseline
    ChangedSSHFiles []string // SSH config files whose hash changed
    // true when baseline is missing entirely (first run)
    NoBaseline bool
    BaselineSavedAt time.Time
}

// HasChanges returns true when any drift was detected.
func (d *SecurityDiff) HasChanges() bool {
    return len(d.NewSUIDs) > 0 || len(d.NewSudoEntries) > 0 ||
        len(d.NewCronEntries) > 0 || len(d.ChangedSSHFiles) > 0
}

// DiffSecurityBaseline compares a saved baseline against a current SecurityInfo.
// Returns a SecurityDiff describing what changed.
// If baseline is nil: returns SecurityDiff{NoBaseline: true}.
func DiffSecurityBaseline(baseline *SecurityBaseline, current *models.SecurityInfo) SecurityDiff
```

For `DiffSecurityBaseline`:
- NewSUIDs: items in `current.SUIDBinaries` not in `baseline.KnownSUIDs`
- RemovedSUIDs: items in `baseline.KnownSUIDs` not in `current.SUIDBinaries`
- NewSudoEntries: items in `current.SudoNopasswd` not in `baseline.SudoNopasswd`
- NewCronEntries: items in `current.SuspectCrons` not in `baseline.SuspectCrons`
- ChangedSSHFiles: files whose current hash != baseline hash
  (compute current hashes via the same `hashSSHConfigFiles()` function)

Use simple slice-to-set conversion for the comparisons — no sorting required,
just membership checking. Missing items (nil slices) are treated as empty.

### Part 3 — Wire into `cmd/security.go`

Read the existing `cmd/security.go` first to understand how it's structured.
Add two new flags:

```go
securityCmd.Flags().Bool("save-baseline", false, "save current security state as drift baseline")
securityCmd.Flags().Bool("drift", false, "compare current security state against saved baseline")
```

In `runSecurity()`:

**`--save-baseline` path:**
1. Collect SecurityInfo (same as normal run)
2. Call `baseline.BuildSecurityBaseline(info)`
3. Call `baseline.SaveSecurityBaseline(b)`
4. Print: `✅  Security baseline saved to ~/.dsd/security-baseline.json`
5. Print: `    SUID binaries: N | Sudo NOPASSWD: N | Suspect crons: N | SSH configs: N`
6. Return (don't print the full security report)

**`--drift` path:**
1. Collect SecurityInfo (same as normal run)
2. Load baseline: `baseline.LoadSecurityBaseline()`
3. If no baseline: print `ℹ️  No security baseline found. Run: dsd security --save-baseline`; return
4. Compute diff: `baseline.DiffSecurityBaseline(saved, info)`
5. If no changes: print `✅  No security drift detected since <baseline date>`; return
6. If changes: print the drift report (see output format below)

**Output format for `--drift` when changes found:**

```
🔍 Security drift since 2026-06-01 14:30:00

New SUID binaries (not in baseline):
  ❌  /usr/local/bin/custom-tool  [investigate: ls -la && file]

Changed SSH config files:
  ⚠️  /etc/ssh/sshd_config  (modified since baseline)
     → Review: diff <(cat /etc/ssh/sshd_config) <(dsd security --show-baseline-ssh)
     → Or: git diff if sshd_config is version-controlled

New sudoers NOPASSWD entries:
  ⚠️  deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app

New suspect cron entries:
  ⚠️  root: * * * * * /tmp/run.sh >> /etc/passwd

────────────────────────────────────────────────────────
⚠️  4 security change(s) since baseline (2026-06-01)
   → Update baseline when changes are intentional: dsd security --save-baseline
```

The drift output should use the same styling as the existing security output
(look at how `printSecurity` formats output in the existing code).

### Part 4 — Heuristics for drift insights

In `internal/analysis/heuristics.go`, find `checkSecurity()`. Add a new
sub-function `checkSecurityDrift()` that takes `*baseline.SecurityDiff` and
returns `[]models.Insight`. Wire it when drift data is available.

```go
// New SUID binary = CRIT (most serious — privilege escalation vector)
if len(diff.NewSUIDs) > 0 {
    insight("CRIT", "Hardening",
        fmt.Sprintf("%d new SUID binary(ies) since last security baseline", len(diff.NewSUIDs)),
        ...hints...)
}
// Changed SSH config = WARN
// New sudo NOPASSWD = WARN
// New suspect cron = WARN
```

**Do NOT wire this into the normal `dsd health` run.** The drift check is
`dsd security --drift` only. Health runs should remain fast and baseline-free.
The heuristics function is useful for the `--drift` output path only.

### Part 5 — Tests

New file: `internal/baseline/security_baseline_test.go`

Required tests:
```go
TestBuildSecurityBaseline_PopulatesFields
TestDiffSecurityBaseline_NewSUIDDetected
TestDiffSecurityBaseline_RemovedSUIDDetected
TestDiffSecurityBaseline_NewSudoEntryDetected
TestDiffSecurityBaseline_NoDriftWhenIdentical
TestDiffSecurityBaseline_NoBaselineReturnsFlag
TestSecurityDiffHasChanges_TrueWhenNewSUIDs
TestSecurityDiffHasChanges_FalseWhenEmpty
```

All tests should use in-memory `SecurityInfo` structs — no disk I/O required
for the diff logic. The `SaveSecurityBaseline`/`LoadSecurityBaseline` functions
can be tested with a temp dir.

---

## Rules and constraints

**DO NOT:**
- Change the `Collect()` signature on SecurityCollector
- Touch `dsd health` — drift is `dsd security --drift` only
- Use any external diff tools — pure Go slice comparison
- Hash file contents in the SecurityInfo model — hashing happens in baseline layer only

**DO:**
- Keep the baseline store as a flat JSON file in `~/.dsd/` — no sqlite, no boltdb
- Guard all file reads with proper error handling — missing files are not errors
  (baseline might not exist, SSH config might not exist on macOS)
- The `hashSSHConfigFiles` function: returns empty map on non-Linux or when
  `/etc/ssh/` doesn't exist — graceful, no errors
- Build tag: no build tag needed — `security_baseline.go` works on all platforms
  (the SSH config paths just won't exist on macOS, and the function handles that)

---

## Verification steps

```bash
# 1. Build
go build ./...

# 2. Tests
go test -race ./internal/baseline/...
go test -race ./...

# 3. Lint
golangci-lint run ./...

# 4. Save baseline on PVE01
make release
scp dist/dsd-linux-amd64 root@192.168.10.20:/tmp/dsd
ssh root@192.168.10.20 '/tmp/dsd security --save-baseline 2>/dev/null'
# Expected: "✅ Security baseline saved..."

# 5. Verify no drift immediately after saving
ssh root@192.168.10.20 '/tmp/dsd security --drift 2>/dev/null'
# Expected: "✅ No security drift detected since <timestamp>"

# 6. Simulate SUID drift — add a test SUID binary, run --drift, clean up
ssh root@192.168.10.20 '
  cp /bin/ls /tmp/test-suid-bin
  chmod u+s /tmp/test-suid-bin
  /tmp/dsd security --drift 2>/dev/null | grep -E "SUID|drift|New"
  rm /tmp/test-suid-bin
'
# Expected: "❌ 1 new SUID binary" entry in drift output

# 7. Save-baseline on AlmaLinux CT 213 too
scp dist/dsd-linux-amd64 root@192.168.10.8:/tmp/dsd
ssh root@192.168.10.8 '/tmp/dsd security --save-baseline 2>/dev/null'
ssh root@192.168.10.8 '/tmp/dsd security --drift 2>/dev/null'
```

---

## Commit message

```
feat(security): dsd security --drift and --save-baseline (V2 Security Drift)

- internal/baseline/security_baseline.go: SecurityBaseline struct,
  SaveSecurityBaseline (atomic), LoadSecurityBaseline, BuildSecurityBaseline,
  hashSSHConfigFiles (SHA-256, no external tools), DiffSecurityBaseline,
  SecurityDiff.HasChanges()
- cmd/security.go: --save-baseline and --drift flags; save-baseline prints
  counts and exits; drift loads baseline, computes diff, prints formatted report
- analysis/heuristics.go: checkSecurityDrift() — new SUID=CRIT,
  changed SSH config/sudo/cron=WARN (used by --drift only, not dsd health)
- internal/baseline/security_baseline_test.go: 8 tests
- Verified: PVE01 baseline save + no-drift clean run + SUID injection detection
```
