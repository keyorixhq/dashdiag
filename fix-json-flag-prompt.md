# Fix: --json silently ignored in 6 commands

## Problem

`--json` is a global flag registered in `cmd/root.go` for every command.
Six commands register it but never read it — `DetectMode` is called with
hardcoded `""` so the flag is silently ignored and human output is produced.

The fix is identical for all six: read the global `--json` flag and pass
it to `DetectMode` as the `outputFmt` argument.

**Commands that need fixing:**
- `cmd/disk.go` — has ModeJSON branch already written, just never reached
- `cmd/docker.go` — no JSON branch at all, needs branch added
- `cmd/k8s.go` — no JSON branch, needs branch added
- `cmd/security.go` — no JSON branch, needs branch added
- `cmd/thermal.go` — no JSON branch, needs branch added
- `cmd/processes.go` — no JSON branch, needs branch added

**Commands that are already correct (do NOT touch):**
`health`, `cpu`, `gpu`, `cron`, `logs`, `proc`, `kvm`, `pve`, `cve`,
`timeline`, `tls`, `hardware`, `cis`, `net`, `services`

---

## The fix pattern

Look at how `cmd/cron.go` does it correctly — use that as the template:

```go
// Read --json from the global flag set
jsonOut, _ := cmd.Flags().GetBool("json")
outputFmt := ""
if jsonOut {
    outputFmt = "json"
}
mode := output.DetectMode(plain, false, outputFmt)
```

Then add a `ModeJSON` branch before the human-output section.

---

## Per-command instructions

### cmd/disk.go

The `ModeJSON` branch already exists at line 73:
```go
if mode == output.ModeJSON {
    return outputJSON(os.Stdout, info)
}
```

The only fix needed is line 37 — replace:
```go
mode := output.DetectMode(plain, false, "")
```
with:
```go
jsonOut, _ := cmd.Flags().GetBool("json")
outputFmt := ""
if jsonOut {
    outputFmt = "json"
}
mode := output.DetectMode(plain, false, outputFmt)
```

That's it for disk — the JSON output function is already there.

### cmd/docker.go

Same fix to `DetectMode` call. Then add a `ModeJSON` branch.

Find where `printDocker(info, mode)` or the main output is called.
Before that, add:

```go
if mode == output.ModeJSON {
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    return enc.Encode(info)
}
```

`encoding/json` is already imported (it's used elsewhere in the file).
`info` is `*models.DockerInfo` — already has full JSON tags.

### cmd/k8s.go

Same DetectMode fix. Then add ModeJSON branch before the human output call:

```go
if mode == output.ModeJSON {
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    return enc.Encode(info)
}
```

`info` is `*models.K8sInfo` — already has JSON tags.

### cmd/security.go

Same DetectMode fix. Then add ModeJSON branch:

```go
if mode == output.ModeJSON {
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    return enc.Encode(info)
}
```

`info` is `*models.SecurityInfo` — already has JSON tags.
Add `"encoding/json"` to imports if not already present.

### cmd/thermal.go

Same pattern. `info` is `*models.ThermalInfo` — already has JSON tags.

### cmd/processes.go

Same pattern. `info` is `*models.ProcessesInfo` — already has JSON tags.

---

## What to check before each edit

For each command file, before editing:
1. Confirm the exact variable name holding the collector result (it varies —
   might be `info`, `result`, `data`, or something else)
2. Confirm `encoding/json` is imported or add it
3. Confirm the result type has JSON tags (all models do — just double-check)
4. Place the ModeJSON branch AFTER the collector finishes but BEFORE any
   human-output printing begins

---

## Verification

```bash
# Build first
go build ./...

# Test each fixed command produces valid JSON
./dsd disk --json 2>/dev/null | python3 -m json.tool > /dev/null && echo "disk: OK"
./dsd thermal --json 2>/dev/null | python3 -m json.tool > /dev/null && echo "thermal: OK"
./dsd processes --json 2>/dev/null | python3 -m json.tool > /dev/null && echo "processes: OK"

# For docker/k8s/security — deploy to linux and test
make release
scp dist/dsd-linux-amd64 root@192.168.10.20:/tmp/dsd
ssh root@192.168.10.20 '/tmp/dsd security --json 2>/dev/null | python3 -m json.tool > /dev/null && echo "security: OK"'
ssh root@192.168.10.20 '/tmp/dsd docker --json 2>/dev/null | python3 -m json.tool > /dev/null && echo "docker: OK"'

# Full test suite
go test -race ./...
golangci-lint run ./...
```

---

## Commit message

```
fix: --json flag now works in disk, docker, k8s, security, thermal, processes

All 6 commands were registering --json via root.go but calling
DetectMode(plain, false, "") — hardcoded empty outputFmt meant the
global flag was silently ignored and human output was always produced.

- cmd/disk.go: pass outputFmt to DetectMode (ModeJSON branch already existed)
- cmd/docker.go: pass outputFmt + add ModeJSON branch (enc.Encode DockerInfo)
- cmd/k8s.go: pass outputFmt + add ModeJSON branch (enc.Encode K8sInfo)
- cmd/security.go: pass outputFmt + add ModeJSON branch (enc.Encode SecurityInfo)
- cmd/thermal.go: pass outputFmt + add ModeJSON branch (enc.Encode ThermalInfo)
- cmd/processes.go: pass outputFmt + add ModeJSON branch (enc.Encode ProcessesInfo)
```
