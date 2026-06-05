# Spec — cloud-init health check (`dsd health` collector)

**Status:** APPROVED, building. From BACKLOG "Candidate features → OpenStack/cloud
guests": *"cloud-init health (build this first if built at all)."* Explicitly called
out as **generic to every cloud-init platform** (AWS/GCP/Oracle/OpenStack + any Debian
VM provisioned with cloud-init), not OpenStack-only — so it pays off broadly and is the
one cloud-candidate worth building ahead of demand. Testable on existing KVM VMs; no
cloud account required.

## Goal

Catch the common **"instance booted but never finished configuring"** failure: cloud-init
ran and errored (network/user-data/module failure), leaving the box up but misconfigured —
no SSH keys, missing packages, half-applied config. Today `dsd health` is silent on it.

## Scope (v1)

A health-only collector. **No `dsd cloudinit` standalone subcommand** — folds into
`dsd health` like CloudMeta/Auditd. Single cheap, non-blocking local check.

### Detection / gate — `CloudInitAvailable() bool`

Zero-cost on non-cloud-init hosts (same gate pattern as `KVMAvailable`/`SteamOSAvailable`).
True when **either**:
- `exec.LookPath("cloud-init")` succeeds, **or**
- `/run/cloud-init/status.json` exists (the runtime status file cloud-init writes).

Both cheap; the run-file check covers minimal images where the CLI is pruned but the
datasource still ran.

### Collection — `CloudInitCollector`

Run `cloud-init status --format=json` with a short timeout. **This does NOT block** —
`status` (without `--wait`) just reads `/run/cloud-init/status.json` and returns
immediately. NEVER pass `--wait`.

Parse the JSON. Fields of interest (cloud-init ≥ 20.x):
- `status` — `"done" | "running" | "error" | "disabled" | "not run"`
- `extended_status` — e.g. `"degraded done"` (cloud-init ≥ 23.x; recoverable-error state)
- `boot_status_code` — e.g. `"enabled-by-..."`, `"disabled-by-..."`
- `datasource` — e.g. `"nocloud"`, `"ec2"`, `"gce"`, `"openstack"`
- `errors` — array of fatal error strings
- `recoverable_errors` — object keyed by level (`WARNING`/`ERROR`) → array; flatten to strings
- `last_update`

**Fallback** for old cloud-init that lacks `--format=json`: run plain `cloud-init status`,
parse the single `status: <value>` line. `errors`/`extended_status` simply stay empty.

Model `models.CloudInitInfo`:
```go
type CloudInitInfo struct {
    Available         bool     `json:"available"`
    Status            string   `json:"status"`
    ExtendedStatus    string   `json:"extended_status,omitempty"`
    BootStatusCode    string   `json:"boot_status_code,omitempty"`
    Datasource        string   `json:"datasource,omitempty"`
    Errors            []string `json:"errors,omitempty"`
    RecoverableErrors []string `json:"recoverable_errors,omitempty"`
    LastUpdate        string   `json:"last_update,omitempty"`
}
```

### Heuristics — `checkCloudInit(c models.CloudInitInfo) []models.Insight`

`!Available` → `nil` (section absent — zero noise).

| Condition | Level | Message |
|---|---|---|
| `status == "error"` (or `len(Errors) > 0`) | **CRIT** | `cloud-init failed — instance configuration incomplete (datasource: <ds>)` |
| `extended_status` contains `"degraded"` OR `len(RecoverableErrors) > 0` | **WARN** | `cloud-init completed with recoverable errors` |
| `status == "running"` | **INFO** | `cloud-init still running — instance configuration in progress` |
| `done` (clean) / `disabled` / `not run` | — | `nil` (silent — healthy or N/A) |

Hints (CRIT): include up to the first 3 error strings, then
`to inspect: cloud-init status --long` and
`logs: /var/log/cloud-init.log, /var/log/cloud-init-output.log`.
Hints (WARN): include recoverable-error strings + the same inspect line.

### Wiring

- `cmd/health.go` `buildHealthCollectors`: `if collectors.CloudInitAvailable() { cols = append(cols, collectors.NewCloudInitCollector()) }` (place near CloudMeta/Auditd).
- `internal/analysis/heuristics.go`: add `models.CloudInitInfo` / `*models.CloudInitInfo`
  dispatch cases → `checkCloudInit`.
- `internal/render/health.go`: add `"CloudInit"` to the section-order slice (near `"CloudMeta"`).

### Files

```
internal/models/cloudinit.go              (new)
internal/collectors/cloudinit_linux.go    (new — collector + gate + parse)
internal/collectors/cloudinit_notlinux.go (new — stub, gate=false)
internal/analysis/heuristics.go           (edit — checkCloudInit + 2 dispatch cases)
internal/analysis/cloudinit_test.go       (new — heuristic table tests)
internal/collectors/cloudinit_parse_test.go (new — JSON + text parse tests)
cmd/health.go                             (edit — gate + append)
internal/render/health.go                 (edit — section order)
```

### Tests

- Parse: real `cloud-init status --format=json` fixtures for `done`, `error` (with
  `errors`), `degraded done` (with `recoverable_errors`), `running`, and a plain-text
  `status: done` fallback.
- Heuristics: error→CRIT, degraded→WARN, recoverable→WARN, running→INFO, done→nil,
  not-Available→nil.

### Out of scope (v1)

`cloud-init analyze blame` boot-timing, per-module breakdown, metadata-service
reachability (separate candidate), any `--wait`/blocking behaviour.

### Validation

Build both platforms (`go build ./...` + `GOOS=linux`). Deploy to a cloud-init VM
(Debian VM 101 / Ubuntu CT 202 on pve01 are provisioned via cloud-init) and confirm
`dsd health` shows the section only where cloud-init is present and stays silent on the
Mac and on non-cloud-init guests.
