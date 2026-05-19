# DashDiag — Claude Code Project Context

> All architecture rules, coding patterns, security rules, and testing rules
> are in `.cursorrules`. Claude Code reads both files. The rules there are
> NON-NEGOTIABLE. Read `.cursorrules` before writing any code.

---

## Current Phase: IMPLEMENTATION (Sprint 1)

Research is complete. ~80 sources processed. Gap spec is saturated.
**DashDiag_Gap_Specs.md** is the single source of truth for what to build.
**BUILD_KICKOFF.md** is the sprint plan with effort estimates and file targets.

---

## What Already Ships

```
dsd health       ✅ fast + deep
dsd net          ✅ fast + deep
dsd logs         ✅ fast + deep
dsd services     ✅ fast only  ← deep spec in Gap_Specs § Spec 1
dsd proc         ✅ fast + deep
dsd docker       ✅ fast only  ← 15 addendums (7a–7o) in Gap_Specs
dsd k8s          ✅ fast only  ← Spec 23 + 23a–23g extensions in Gap_Specs
```

**Do not rewrite or restructure these. Only extend them.**

---

## What Gets Built Next (Priority Order)

### Sprint 1 — Extend Existing
1. `dsd services deep` — systemd failure diagnosis (Gap_Specs § Spec 1, ~2d)
2. `dsd health` — active session list via `w -h` (Gap_Specs § Spec H1, ~0.5d)
3. `dsd net deep` — DNS resolver audit (Gap_Specs § Spec 2, ~1d)
4. `dsd logs` — severity summary + crash files (Gap_Specs § Spec 3, ~1.5d)

### Sprint 2 — New Commands
5. `dsd disk` fast+deep — filesystems, SMART, ZFS, LVM (Gap_Specs § Spec 4, 4a, 4b)
6. `dsd security` fast — SSH config, sudo, SUID, open ports (Gap_Specs § Spec 13)

### Sprint 3 — Docker + k8s Full Build
7. `dsd docker` addendums 7a–7o (15 new checks via Docker socket API)
8. `dsd k8s` Spec 23 fast extensions + addendums 23a–23g

### Sprint 4 — Virtualisation
9. `dsd pve` — Proxmox VE diagnostics (Gap_Specs § Spec 24)
10. `dsd kvm` — KVM/libvirt diagnostics (Gap_Specs § Spec 15)
11. `dsd disk deep` extensions

---

## How to Use the Spec

Every item in `DashDiag_Gap_Specs.md` has:
- **Pain source** — why admins need this
- **What to add** — exact commands, /proc paths, data sources
- **Output example** — copy this as your target UX
- **JSON schema** — what `--json` must include
- **Acceptance criteria** — checklist, tick off before marking done

---

## Key Implementation Notes

### k8s addendums 23a–23g — one shared JSON call
Replace the existing `--no-headers` pod call with one JSON call.
All 4 fast addendums (23a, 23b, 23c, 23f) parse the same response.
```go
out, err := k8sRun(ctx, bin, "get", "pods", "-A", "-o", "json")
// Parse: deletionTimestamp (23a), initContainerStatuses (23b),
//        lastState.terminated.message (23c), ownerReferences (23f)
```

### dsd docker addendums — socket API only, no docker CLI
All checks via HTTP to the Docker socket. No dependency on docker binary.
Podman socket supported via the same API surface.

### dsd pve — pvesh with timeout
```go
cmd := exec.CommandContext(ctx, "pvesh", "get",
    "/nodes/localhost/status", "--output-format", "json")
// Wrap ALL pvesh calls with 10s context timeout
// pvesh is always at /usr/bin/pvesh on PVE nodes
```

### dsd disk — ZFS gate (zero overhead on non-ZFS)
```go
// Gate 1: zpool binary exists
// Gate 2: /proc/mounts has a zfs entry
// If gate passes: zpool status -x first (empty = all healthy, no parsing)
// Only parse full zpool status when -x produces output
```

### Bridge STP detection (dsd pve deep)
```go
// /sys/class/net/<bridge>/bridge/stp_state
// 1 = STP enabled → WARN (causes ~30s boot delay)
// 0 = STP disabled → OK
```

---

## Test Machines

| Command | Primary | Key scenarios |
|---|---|---|
| `dsd services deep` | RHEL laptop | Mask a unit, NeedsDaemonReload |
| `dsd disk` | Proxmox host | ZFS pools, LVM, HDD+SSD+NVMe mix |
| `dsd docker` | RHEL laptop | OOM-kill container, check 7a/7e |
| `dsd k8s` | RHEL laptop (k3s) | CrashLoop pod, PVC Pending |
| `dsd pve` | Proxmox host | Run pveperf, stop a VM, backup audit |
| `dsd kvm` | RHEL laptop | Paused VM, missing disk image path |

---

## Gap Spec File Locations

```
DashDiag_Gap_Specs.md    ← 51 spec items, ~58d total, RESEARCH COMPLETE
BUILD_KICKOFF.md         ← Sprint plan with effort estimates
BACKLOG.md               ← Full feature backlog (sprint-ordered)
```

---

## New Files to Create

```
cmd/disk.go                          Sprint 2
cmd/security.go                      Sprint 2
cmd/pve.go                           Sprint 4
cmd/kvm.go                           Sprint 4
internal/collectors/disk.go          Sprint 2
internal/collectors/disk_linux.go    Sprint 2
internal/collectors/security.go      Sprint 2
internal/collectors/security_linux.go Sprint 2
internal/collectors/pve.go           Sprint 4
internal/collectors/kvm.go           Sprint 4
internal/collectors/kvm_linux.go     Sprint 4
internal/models/disk.go              Sprint 2
internal/models/security.go          Sprint 2
internal/models/pve.go               Sprint 4
internal/models/kvm.go               Sprint 4
```

Follow the pattern of `internal/collectors/docker.go` and
`internal/models/docker.go` exactly when creating new collectors.
