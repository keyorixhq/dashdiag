# V2 Correlation Rules — 3 new rules

## What this does in one sentence

Adds three new correlation rules to `internal/analysis/correlate.go` and the
one small model+collector change needed to make the third rule possible.
No command changes. No interface changes beyond extending `CorrelateDeep`.

---

## Read these files completely before writing anything

```
internal/analysis/correlate.go          (466 lines — full engine)
internal/analysis/correlate_test.go     (553 lines — test patterns)
internal/models/io.go                   (20 lines)
internal/models/sysctl.go               (30 lines)
internal/models/tls.go                  (20 lines)
internal/collectors/sysctl.go           (106 lines — where to add uptime read)
cmd/health.go lines 148-155             (CorrelateDeep call site)
cmd/health.go lines 529-551             (extractOOM / extractDocker — copy this pattern)
```

---

## Change 1 of 4 — Add `UptimeSeconds` to SysctlInfo

**File:** `internal/models/sysctl.go`

Add one field to the end of `SysctlInfo`, before the closing brace:

```go
// UptimeSeconds is the system uptime at collection time from /proc/uptime.
// Used by the correlation engine to detect sysctl drift after a recent reboot.
// Zero when unavailable (non-Linux, read error).
UptimeSeconds int64 `json:"uptime_seconds,omitempty"`
```

---

## Change 2 of 4 — Populate `UptimeSeconds` in the sysctl collector

**File:** `internal/collectors/sysctl.go`

In `collectLinux()`, after the last `readIntFile` call (line ~68, after
`info.FSInotifyWatches`) and before `info.Workload = detectWorkload()`, add:

```go
// Uptime — used by correlation engine for sysctl-drift-after-reboot detection.
if data, err := os.ReadFile("/proc/uptime"); err == nil {
    if fields := strings.Fields(string(data)); len(fields) >= 1 {
        if f, err := strconv.ParseFloat(fields[0], 64); err == nil {
            info.UptimeSeconds = int64(f)
        }
    }
}
```

All imports (`os`, `strings`, `strconv`) are already present in the file.
No other changes to this file.

---

## Change 3 of 4 — Three new rules in `internal/analysis/correlate.go`

### 3a. Extend `Correlate()` with Rule 1

Inside the existing `Correlate()` function, after the last existing rule call
(`ruleDBusCascade`) and before `return out`, add:

```go
if c, ok := ruleEntropyTLSFailure(idx); ok {
    out = append(out, c)
}
```

Then add the rule function anywhere after the existing rule functions
(keep alphabetical or grouped — your choice, be consistent):

```go
// ruleEntropyTLSFailure fires when the entropy pool is dangerously low while
// TLS certificates are active on the system. Low entropy causes SSL handshakes
// and key-generation operations to stall waiting for randomness — the symptom
// is connection timeouts, not certificate errors, making this hard to diagnose
// without the correlation.
//
// Required signals:
//   - Entropy WARN or CRIT  (pool below 256 bits)
//   - TLS    WARN or CRIT   (expired or expiring-soon certs present)
func ruleEntropyTLSFailure(idx map[string]indexEntry) (Correlation, bool) {
	entropyLow := atLeast(idx, "Entropy", "WARN")
	tlsFired := atLeast(idx, "TLS", "WARN")

	if !entropyLow || !tlsFired {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "Entropy Starvation with TLS Active",
		Level:   "CRIT",
		Summary: "entropy pool is critically low while TLS certificates are in use — SSL handshakes and key operations will stall or time out waiting for randomness",
		Action:  "apt install haveged OR dnf install rng-tools && systemctl enable --now rngd",
		Checks:  []string{"Entropy", "TLS"},
	}, true
}
```

### 3b. Extend `CorrelateDeep()` with Rules 2 and 3

**Current signature (line 386):**
```go
func CorrelateDeep(insights []models.Insight, oom *models.OOMInfo, docker *models.DockerInfo) []Correlation {
```

**New signature:**
```go
func CorrelateDeep(insights []models.Insight, oom *models.OOMInfo, docker *models.DockerInfo, io *models.IOInfo, sysctl *models.SysctlInfo) []Correlation {
```

Inside `CorrelateDeep`, after the existing `ruleDockerOOMCascade` call, add:

```go
if c, ok := ruleIOSingleDeviceDegradation(io); ok {
    out = append(out, c)
}
idx := buildIndex(insights) // build index here if not already available
if c, ok := ruleSysctlNotPersisted(sysctl, idx); ok {
    out = append(out, c)
}
```

**IMPORTANT:** check whether `buildIndex` is already called inside `CorrelateDeep`
before adding a second call. If `Correlate(insights)` is called first (which calls
`buildIndex` internally), you need to call `buildIndex(insights)` separately here
for the sysctl rule — it's cheap (O(n) over insights). Alternatively, restructure
so the index is built once and passed. Keep it simple.

**Rule 2 — IO Single Device Degradation:**

```go
// ruleIOSingleDeviceDegradation fires when one device has critically high
// latency while peer devices on the same system are healthy. This pattern
// points to a single failing or contended drive rather than a storage
// subsystem overload — the remediation differs (replace drive vs reduce load).
//
// Required signals (raw IOInfo, not insights):
//   - At least 2 devices in io.Devices
//   - Exactly 1 device with AwaitMs > 20.0 OR UtilPct > 85.0
//   - At least 1 peer device with AwaitMs < 5.0 AND UtilPct < 60.0
func ruleIOSingleDeviceDegradation(io *models.IOInfo) (Correlation, bool) {
	if io == nil || len(io.Devices) < 2 {
		return Correlation{}, false
	}

	var degraded []models.IODeviceInfo
	var healthy []models.IODeviceInfo
	for _, d := range io.Devices {
		if d.AwaitMs > 20.0 || d.UtilPct > 85.0 {
			degraded = append(degraded, d)
		} else if d.AwaitMs < 5.0 && d.UtilPct < 60.0 {
			healthy = append(healthy, d)
		}
	}

	if len(degraded) != 1 || len(healthy) == 0 {
		return Correlation{}, false
	}

	dev := degraded[0]
	return Correlation{
		Name: "Single Device IO Degradation",
		Level: "CRIT",
		Summary: fmt.Sprintf("%s has critically high IO latency (%.0fms await, %.0f%% util) while %d peer device(s) are healthy — likely a failing or heavily contended drive",
			dev.Name, dev.AwaitMs, dev.UtilPct, len(healthy)),
		Action: fmt.Sprintf("smartctl -a /dev/%s && iostat -x 1 5", dev.Name),
		Checks: []string{"IO"},
	}, true
}
```

**Rule 3 — Sysctl Not Persisted:**

```go
// ruleSysctlNotPersisted fires when sysctl parameters are at non-recommended
// values AND the system rebooted recently (uptime < 1 hour). This combination
// indicates the operator applied a fix with `sysctl -w` but did not persist it
// to /etc/sysctl.d/ — the fix was lost on reboot.
//
// Required signals:
//   - Sysctl WARN or CRIT   (some parameter is misconfigured)
//   - sysctl.UptimeSeconds > 0 AND < 3600   (rebooted in the last hour)
func ruleSysctlNotPersisted(sysctl *models.SysctlInfo, idx map[string]indexEntry) (Correlation, bool) {
	if sysctl == nil || sysctl.UptimeSeconds <= 0 || sysctl.UptimeSeconds >= 3600 {
		return Correlation{}, false
	}
	if !atLeast(idx, "Sysctl", "WARN") {
		return Correlation{}, false
	}

	uptimeMin := sysctl.UptimeSeconds / 60
	return Correlation{
		Name:  "Sysctl Parameter Not Persisted",
		Level: "WARN",
		Summary: fmt.Sprintf("system rebooted %d minute(s) ago and sysctl parameters are still at non-recommended values — the previous fix was applied with sysctl -w but not written to /etc/sysctl.d/",
			uptimeMin),
		Action: "echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf && sysctl -p /etc/sysctl.d/99-dsd.conf",
		Checks: []string{"Sysctl"},
	}, true
}
```

`fmt` is already imported in `correlate.go`. Verify before adding a new import.

---

## Change 4 of 4 — Update the CorrelateDeep call site

**File:** `cmd/health.go`

**Line 153 — update the call:**
```go
// Before:
correlations := analysis.CorrelateDeep(insights, extractOOM(results), extractDocker(results))

// After:
correlations := analysis.CorrelateDeep(insights, extractOOM(results), extractDocker(results), extractIO(results), extractSysctl(results))
```

**Add two new extractor functions** after the existing `extractDocker` function
(currently ends at line 551). Copy the exact pattern of `extractDocker`:

```go
// extractIO type-asserts *models.IOInfo from a runner results slice.
// Returns nil when the IO collector was not included or returned an error.
func extractIO(results []runner.Result) *models.IOInfo {
	for _, r := range results {
		if r.Err == nil {
			if v, ok := r.Data.(*models.IOInfo); ok {
				return v
			}
		}
	}
	return nil
}

// extractSysctl type-asserts *models.SysctlInfo from a runner results slice.
// Returns nil when the Sysctl collector was not included or returned an error.
func extractSysctl(results []runner.Result) *models.SysctlInfo {
	for _, r := range results {
		if r.Err == nil {
			if v, ok := r.Data.(*models.SysctlInfo); ok {
				return v
			}
		}
	}
	return nil
}
```

**Search for ALL other callers of `CorrelateDeep` before finishing:**
```
grep -rn "CorrelateDeep" --include="*.go" .
```
Update every call site to pass the two new nil arguments. In test files, pass
`nil, nil` for the new parameters — existing tests must compile and pass unchanged.

---

## Tests to add in `internal/analysis/correlate_test.go`

Add these at the end of the file. Follow the exact style of existing tests.

First add two helper builders (after the existing `makeDocker` at line ~423):

```go
func makeIO(devices ...models.IODeviceInfo) *models.IOInfo {
	return &models.IOInfo{Devices: devices}
}

func makeSysctl(uptimeSec int64, swappiness int) *models.SysctlInfo {
	return &models.SysctlInfo{
		Available:     true,
		UptimeSeconds: uptimeSec,
		VMSwappiness:  swappiness,
	}
}
```

Then add these test functions:

```go
// ── ruleEntropyTLSFailure ─────────────────────────────────────────────────

func TestEntropyTLSFailureFires(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Entropy", "entropy pool critically low (32 bits)"),
		ins("WARN", "TLS", "2 certificate(s) expiring within 30 days"),
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "Entropy Starvation with TLS Active" {
			found = true
			if c.Level != "CRIT" {
				t.Errorf("expected CRIT, got %q", c.Level)
			}
		}
	}
	if !found {
		t.Error("expected Entropy Starvation with TLS Active to fire")
	}
}

func TestEntropyTLSFailureDoesNotFireWithoutTLS(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Entropy", "entropy pool critically low"),
		// no TLS insight
	}
	for _, c := range Correlate(insights) {
		if c.Name == "Entropy Starvation with TLS Active" {
			t.Error("should not fire without TLS signal")
		}
	}
}

func TestEntropyTLSFailureDoesNotFireWithoutEntropy(t *testing.T) {
	insights := []models.Insight{
		ins("WARN", "TLS", "1 certificate expiring"),
		// no Entropy insight
	}
	for _, c := range Correlate(insights) {
		if c.Name == "Entropy Starvation with TLS Active" {
			t.Error("should not fire without Entropy signal")
		}
	}
}

// ── ruleIOSingleDeviceDegradation ────────────────────────────────────────

func TestIOSingleDeviceDegradationFires(t *testing.T) {
	io := makeIO(
		models.IODeviceInfo{Name: "sda", AwaitMs: 45.0, UtilPct: 92.0}, // degraded
		models.IODeviceInfo{Name: "sdb", AwaitMs: 1.2, UtilPct: 15.0},  // healthy peer
	)
	c, ok := ruleIOSingleDeviceDegradation(io)
	if !ok {
		t.Fatal("expected rule to fire")
	}
	if c.Level != "CRIT" {
		t.Errorf("expected CRIT, got %q", c.Level)
	}
	if !strings.Contains(c.Summary, "sda") {
		t.Errorf("summary should name the degraded device, got: %q", c.Summary)
	}
}

func TestIOSingleDeviceDegradationDoesNotFireWithOnlyOneDevice(t *testing.T) {
	io := makeIO(
		models.IODeviceInfo{Name: "sda", AwaitMs: 50.0, UtilPct: 95.0},
	)
	if _, ok := ruleIOSingleDeviceDegradation(io); ok {
		t.Error("should not fire with only one device")
	}
}

func TestIOSingleDeviceDegradationDoesNotFireWhenBothDegraded(t *testing.T) {
	io := makeIO(
		models.IODeviceInfo{Name: "sda", AwaitMs: 45.0, UtilPct: 92.0},
		models.IODeviceInfo{Name: "sdb", AwaitMs: 30.0, UtilPct: 88.0}, // both degraded
	)
	if _, ok := ruleIOSingleDeviceDegradation(io); ok {
		t.Error("should not fire when both devices are degraded (subsystem overload, not single drive)")
	}
}

func TestIOSingleDeviceDegradationDoesNotFireWithNilIO(t *testing.T) {
	if _, ok := ruleIOSingleDeviceDegradation(nil); ok {
		t.Error("should not fire with nil IOInfo")
	}
}

// ── ruleSysctlNotPersisted ────────────────────────────────────────────────

func TestSysctlNotPersistedFires(t *testing.T) {
	sysctl := makeSysctl(1800, 100) // 30 min uptime, swappiness=100 (bad)
	insights := []models.Insight{
		ins("WARN", "Sysctl", "vm.swappiness=100 is high for a server"),
	}
	idx := buildIndex(insights)
	c, ok := ruleSysctlNotPersisted(sysctl, idx)
	if !ok {
		t.Fatal("expected rule to fire")
	}
	if c.Level != "WARN" {
		t.Errorf("expected WARN, got %q", c.Level)
	}
	if !strings.Contains(c.Summary, "30 minute") {
		t.Errorf("summary should include uptime in minutes, got: %q", c.Summary)
	}
}

func TestSysctlNotPersistedDoesNotFireAfterOneHour(t *testing.T) {
	sysctl := makeSysctl(7200, 100) // 2 hours uptime
	insights := []models.Insight{
		ins("WARN", "Sysctl", "vm.swappiness=100 is high"),
	}
	idx := buildIndex(insights)
	if _, ok := ruleSysctlNotPersisted(sysctl, idx); ok {
		t.Error("should not fire when uptime >= 1 hour (not a recent reboot)")
	}
}

func TestSysctlNotPersistedDoesNotFireWhenSysctlOK(t *testing.T) {
	sysctl := makeSysctl(300, 10) // 5 min uptime, but sysctl is fine
	idx := buildIndex(nil)        // no sysctl insights
	if _, ok := ruleSysctlNotPersisted(sysctl, idx); ok {
		t.Error("should not fire when sysctl has no WARN/CRIT")
	}
}

func TestSysctlNotPersistedDoesNotFireWithNilSysctl(t *testing.T) {
	insights := []models.Insight{ins("WARN", "Sysctl", "bad param")}
	idx := buildIndex(insights)
	if _, ok := ruleSysctlNotPersisted(nil, idx); ok {
		t.Error("should not fire with nil SysctlInfo")
	}
}

// ── CorrelateDeep nil-safety for new params ──────────────────────────────

func TestCorrelateDeepNewParamsNilSafe(t *testing.T) {
	// Must not panic with nil for the new parameters
	corrs := CorrelateDeep(nil, nil, nil, nil, nil)
	_ = corrs // any result is fine, just must not panic
}

func TestCorrelateDeepPreservesExistingRulesWithNewParams(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 97%"),
		ins("CRIT", "Swap", "heavy swap activity: 29979 pages/s"),
		ins("CRIT", "Processes", "5 hung processes"),
	}
	corrs := CorrelateDeep(insights, nil, nil, nil, nil)
	found := false
	for _, c := range corrs {
		if c.Name == "Memory Pressure Cascade" {
			found = true
		}
	}
	if !found {
		t.Error("CorrelateDeep must still fire existing rules after signature change")
	}
}
```

Note: the tests use `strings.Contains` — add `"strings"` to the test file imports
if not already present.

---

## Execution order

1. Change 1: add `UptimeSeconds` to `internal/models/sysctl.go`
2. Change 2: populate it in `internal/collectors/sysctl.go`
3. `go build ./...` — verify models compile before touching correlate
4. Change 3: add the three rules to `correlate.go`
5. Change 4: update `CorrelateDeep` call site and add extractors to `cmd/health.go`
6. Add tests to `correlate_test.go`
7. `go build ./...` — must be clean
8. `go test -race ./internal/analysis/...` — new tests must pass
9. `go test -race ./...` — full suite must be green
10. `golangci-lint run ./...` — no new issues beyond the pre-existing 5

---

## Live verification (after all tests pass)

SSH to AlmaLinux CT 213 (192.168.10.8) via PVE:

```bash
# From PVE01:
pct start 213 2>/dev/null; sleep 3

# Set a bad sysctl inside the CT (do NOT persist it — that's the point):
pct exec 213 -- sysctl -w vm.swappiness=100

# Reboot the CT:
pct reboot 213

# Wait ~20 seconds for boot:
sleep 25

# Deploy and run:
scp dist/dsd-linux-amd64 root@192.168.10.8:/tmp/dsd
ssh root@192.168.10.8 '/tmp/dsd health 2>/dev/null | grep -A3 -E "Sysctl|DIAGNOSIS|Not Persisted"'
```

Expected: `Sysctl` row at WARN (swappiness=100 is bad) AND the correlation
"Sysctl Parameter Not Persisted" appearing in the DIAGNOSIS block.

The Entropy+TLS and SingleDevice rules are fully covered by unit tests and do
not require live firing on the current test matrix.

---

## Commit message

```
feat(correlate): 3 new correlation rules — entropy+TLS, single drive IO, sysctl persist

- ruleEntropyTLSFailure: Entropy WARN/CRIT + TLS WARN/CRIT fires CRIT
  "Entropy Starvation with TLS Active" — explains SSL timeout root cause
- ruleIOSingleDeviceDegradation: 1 degraded device + healthy peers fires CRIT
  "Single Device IO Degradation" — drive failure vs subsystem overload
- ruleSysctlNotPersisted: Sysctl WARN/CRIT + uptime < 1h fires WARN
  "Sysctl Parameter Not Persisted" — detects sysctl -w without sysctl.d
- models/sysctl.go: UptimeSeconds int64 field (from /proc/uptime)
- collectors/sysctl.go: populate UptimeSeconds in collectLinux()
- correlate.go: CorrelateDeep extended with *models.IOInfo + *models.SysctlInfo
  (nil-safe; all existing tests pass with nil for new params)
- cmd/health.go: extractIO + extractSysctl helpers; updated CorrelateDeep call
- correlate_test.go: 13 new tests covering fires/no-fire for all 3 rules,
  nil-safety, and backward compat of existing CorrelateDeep callers
- Live verified: sysctl rule fires on AlmaLinux CT 213 after reboot with
  vm.swappiness=100 set via sysctl -w (not persisted to sysctl.d)
```
