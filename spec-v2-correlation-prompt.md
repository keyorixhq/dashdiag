# V2 Correlation Rules — 3 new rules + Sysctl uptime signal

## Context

DashDiag (`/Users/abeshkov/proj/dashdiag`) has a correlation engine at
`internal/analysis/correlate.go` (466 lines). It already ships 9 rules:
MemoryCascade, HardOOM, IOUnderMemoryPressure, NetworkDegradedUnderLoad,
GPUSustainedLoad, IODrivenLoad, CPUStealUnderLoad, DBusCascade, DockerOOMCascade.

This adds 3 more rules from the backlog:
1. **Entropy low + TLS signals → crypto bootstrapping failure**
2. **IO CRIT on one device + other OK → single drive degradation**
3. **Sysctl drift + recent reboot → parameter not persisted**

Read these files first, completely, before touching anything:
- `internal/analysis/correlate.go` — full engine, all existing rules
- `internal/analysis/correlate_test.go` — all test patterns (553 lines)
- `internal/models/sysctl.go` — SysctlInfo fields
- `internal/models/tls.go` — TLSInfo fields
- `internal/models/io.go` — IOInfo fields (for per-device data)
- `internal/models/entropy.go` (or wherever EntropyInfo is defined)
- `internal/collectors/clock.go` — to see how uptime is currently read

## What to build

### Part 1 — Small model addition: uptime signal in SysctlInfo

`SysctlInfo` (internal/models/sysctl.go) needs one new field:

```go
// UptimeSeconds is the system uptime at collection time, read from
// /proc/uptime. Used by the correlation engine to detect sysctl drift
// after a recent reboot (parameter not persisted).
// Zero when unavailable (non-Linux, or read error).
UptimeSeconds int64 `json:"uptime_seconds,omitempty"`
```

In `internal/collectors/sysctl.go` (or `sysctl_linux.go` — check where
SysctlInfo is populated), add a read of `/proc/uptime` at collection time:

```go
if data, err := os.ReadFile("/proc/uptime"); err == nil {
    fields := strings.Fields(string(data))
    if len(fields) >= 1 {
        if f, err := strconv.ParseFloat(fields[0], 64); err == nil {
            info.UptimeSeconds = int64(f)
        }
    }
}
```

No other changes to SysctlInfo. No test changes needed — just the field + read.

### Part 2 — Three new correlation rules in `internal/analysis/correlate.go`

Add all three to the `Correlate()` function dispatch, same pattern as existing rules.

---

#### Rule 1: `ruleEntropyTLSFailure`

**Logic:** Entropy pool critically low (< 64 bits = CRIT, already flagged)
AND TLS collector found expired or expiring-soon certificates.
This is the "crypto bootstrapping failure" pattern — services that need to
do TLS handshakes or generate keys will stall or fail when entropy is exhausted.

```
Required signals:
  - Entropy CRIT or WARN  (pool below 256 bits)
  - TLS WARN or CRIT      (expired or expiring certs present)
```

The correlation explains *why* TLS is failing — low entropy causes SSL handshakes
to block waiting for randomness, which manifests as connection timeouts, not cert
errors. Distinguishing this from a pure cert problem is high value.

```go
func ruleEntropyTLSFailure(idx map[string]indexEntry) (Correlation, bool) {
    // ...
    return Correlation{
        Name:    "Entropy Starvation with TLS Active",
        Level:   "CRIT",
        Summary: "entropy pool is critically low while TLS certificates are in use — SSL handshakes and key operations will stall or time out waiting for randomness",
        Action:  "install haveged or rng-tools to feed the entropy pool: apt install haveged OR dnf install rng-tools && systemctl enable --now rngd",
        Checks:  []string{"Entropy", "TLS"},
    }, true
}
```

---

#### Rule 2: `ruleIOSingleDeviceDegradation`

**Logic:** This requires access to the raw IOInfo collector data, not just the
insight index. Add it to `CorrelateDeep()` (which already takes raw data), adding
an `*models.IOInfo` parameter.

```
Required signals (from raw IOInfo, not just insights):
  - At least 2 devices present in IOInfo.Devices
  - Exactly ONE device has await > 20ms (or util > 85%)
  - At least one OTHER device is healthy (await < 5ms)
```

This pattern — one device critically degraded while peers are healthy — points to
single drive failure rather than storage subsystem overload. Actionable because the
fix (replace the drive) differs from IO-under-pressure (reduce workload).

Update `CorrelateDeep` signature:
```go
func CorrelateDeep(insights []models.Insight, oom *models.OOMInfo, docker *models.DockerInfo, io *models.IOInfo) []Correlation
```

Update all call sites of `CorrelateDeep` (check cmd/health.go and any test files)
to pass the IOInfo. Extract it from results the same way OOM and Docker are extracted
— look at `extractOOM` and `extractDocker` helper functions in cmd/health.go for
the pattern.

Add `extractIO(results []runner.Result) *models.IOInfo` in cmd/health.go.

Rule function signature:
```go
func ruleIOSingleDeviceDegradation(io *models.IOInfo) (Correlation, bool)
```

Thresholds to use (match the existing IOInfo heuristics):
- Degraded device: AwaitMs > 20.0 OR UtilPct > 85.0
- Healthy peer: AwaitMs < 5.0 AND UtilPct < 60.0
- Fires only when: 1 degraded + at least 1 healthy peer in the same results

```go
return Correlation{
    Name:    "Single Device IO Degradation",
    Level:   "CRIT",
    Summary: fmt.Sprintf("%s has critically high IO latency (%.1fms await) while peer devices are healthy — likely a failing or heavily contended drive", degradedName, degradedAwait),
    Action:  fmt.Sprintf("check drive health: smartctl -a /dev/%s && iostat -x 1 5", degradedName),
    Checks:  []string{"IO"},
}, true
```

---

#### Rule 3: `ruleSysctlNotPersisted`

**Logic:** Uses the new `UptimeSeconds` field. Fires when:
- System rebooted recently (uptime < 1 hour = 3600 seconds)
- AND Sysctl WARN or CRIT is present (parameters are still at non-recommended values)

The diagnosis: if parameters are misconfigured right after a reboot, it means the
sysctl.conf / sysctl.d fix was never persisted — the admin applied it with
`sysctl -w` but forgot to write it to `/etc/sysctl.d/`.

This is a high-value insight because the symptom (parameter at bad value) is the
same whether the fix was never applied OR was applied but not persisted. The uptime
signal disambiguates.

```
Required signals:
  - Sysctl WARN or CRIT (some parameter is at a non-recommended value)
  - SysctlInfo.UptimeSeconds > 0 AND < 3600 (rebooted in the last hour)
```

This rule cannot be implemented purely from the insight index — it needs the raw
UptimeSeconds value. Add it to `CorrelateDeep()` alongside the IOInfo addition,
taking an additional `*models.SysctlInfo` parameter. Extract it from results
similarly to IOInfo.

Rule function:
```go
func ruleSysctlNotPersisted(sysctl *models.SysctlInfo, idx map[string]indexEntry) (Correlation, bool)
```

```go
return Correlation{
    Name:    "Sysctl Parameter Not Persisted",
    Level:   "WARN",
    Summary: fmt.Sprintf("system rebooted %.0f minutes ago and sysctl parameters are still at non-recommended values — the previous fix was likely applied with sysctl -w but not written to /etc/sysctl.d/", float64(sysctl.UptimeSeconds)/60),
    Action:  "persist the fix: echo 'param=value' >> /etc/sysctl.d/99-dsd.conf && sysctl -p /etc/sysctl.d/99-dsd.conf",
    Checks:  []string{"Sysctl"},
}, true
```

### Part 3 — Tests in `internal/analysis/correlate_test.go`

Follow the exact test pattern from existing tests. Each rule needs:
1. A "fires" test — signals present, correlation returned with correct Name/Level
2. A "does not fire" test — missing a required signal, empty result
3. For time-aware rules (sysctl): test with uptime=30min (fires) and uptime=2h (no fire)

Test the `CorrelateDeep` signature change with a nil-safe test:
- Pass nil for new parameters → must not panic, returns same results as before

### Part 4 — Update CorrelateDeep call sites

`CorrelateDeep` is called in `cmd/health.go`. Update the call site:
1. Add `extractIO` helper (pattern: same as `extractDocker` at line ~535)
2. Add `extractSysctl` helper (same pattern)
3. Update the `CorrelateDeep(...)` call to pass both

Search the codebase for ALL calls to `CorrelateDeep`:
```bash
grep -rn "CorrelateDeep" --include="*.go"
```
Update every call site. Test files that call it need updating too.

## Rules and constraints

**DO NOT:**
- Change `Correlate()` signature (no new params — pure insight index)
- Break any existing test — all 9 rules' tests must still pass
- Add any new imports beyond what's already in correlate.go (no external deps)
- Change any model field names or remove existing fields

**DO:**
- Keep `CorrelateDeep` nil-safe for all new parameters (nil io → skip rule 2, nil sysctl → skip rule 3)
- Follow exact code style of existing rules: short function, clear comment block documenting required signals, separate `Correlation{}` construction
- Use the existing `atLeast()` and `exact()` helpers — don't inline string comparisons

## Verification steps

1. `go build ./...` — exit 0
2. `go test -race ./internal/analysis/...` — all green
3. `go test -race ./...` — full suite green
4. `golangci-lint run ./...` — no new issues beyond pre-existing 5
5. Deploy to AlmaLinux CT (192.168.10.8) and run `dsd health`:
   - Deliberately set a bad sysctl: `sysctl -w vm.swappiness=100`
   - Reboot the CT: `pct reboot 213` from PVE01
   - After reboot, run `dsd health` — expect: Sysctl WARN + "Sysctl Parameter Not Persisted" correlation
6. The Entropy+TLS and SingleDevice rules can be verified via unit tests alone —
   no live firing expected on the test matrix (no TLS collector running, no degraded drives)

## Commit message template

```
feat(correlate): 3 new correlation rules — entropy+TLS, single drive IO, sysctl persist

- ruleEntropyTLSFailure: entropy pool low + TLS active → crypto starvation
- ruleIOSingleDeviceDegradation: 1 degraded device + healthy peers → drive failure
- ruleSysctlNotPersisted: sysctl WARN + uptime < 1h → parameter not written to sysctl.d
- models/sysctl.go: add UptimeSeconds field (from /proc/uptime)
- collectors/sysctl_linux.go: populate UptimeSeconds at collection time
- CorrelateDeep: extended with *models.IOInfo + *models.SysctlInfo params (nil-safe)
- cmd/health.go: extractIO + extractSysctl helpers, updated CorrelateDeep call
- correlate_test.go: fires/no-fire tests for all 3 new rules
- Live verified: Sysctl rule fires on AlmaLinux CT 213 after reboot with bad swappiness
```
