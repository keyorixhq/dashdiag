# DashDiag — Build Kickoff Summary
**Date: May 2026 | Phase: Implementation**
**Research: COMPLETE (~80 sources, saturated)**

This document is your single-page reference before each Claude Code session.
Keep it open alongside DashDiag_Gap_Specs.md when building.

> Claude Code reads `CLAUDE.md` and `.cursorrules` automatically.
> Architecture rules in `.cursorrules` are NON-NEGOTIABLE.

---

## The Ironclad Rule

> **Never build deep before fast is in production use.**

Fast = runs in < 3s, ships first, gets real-world feedback.
Deep = opt-in with `--deep`, ships after fast is validated on real hardware.

---

## What Already Exists (Do Not Rebuild)

| Command | File | Status |
|---|---|---|
| `dsd health` | cmd/health.go | ✅ Shipped |
| `dsd net` | cmd/net.go | ✅ Shipped |
| `dsd logs` | cmd/logs.go | ✅ Shipped |
| `dsd services` | cmd/services.go | ✅ Shipped (fast only) |
| `dsd proc` | cmd/proc.go | ✅ Shipped |
| `dsd docker` | cmd/docker.go | ✅ Shipped (fast only, extend with 7a–7o) |
| `dsd k8s` | cmd/k8s.go | ✅ Shipped (fast only, extend with Spec 23) |
| 18 collectors | internal/collectors/ | ✅ Shipped |

---

## Sprint Plan

### Sprint 1 — Extend Existing Commands (Week 1–2)
*Target: ship on real hardware before moving on.*

| Task | Spec | Effort | File |
|---|---|---|---|
| `dsd services deep` — systemd failure diagnosis | Spec 1 | ~2d | collectors/services_deep_linux.go (new) |
| `dsd health` — active session list (`w -h`) | Spec H1 | ~0.5d | collectors/health.go (extend) |
| `dsd net deep` — DNS resolver audit | Spec 2 | ~1d | collectors/net.go (extend) |
| `dsd logs` — severity summary + crash files | Spec 3 | ~1.5d | collectors/logs.go (extend) |

**Sprint 1 deliverable:** All existing commands have their deep variants or
key fast gaps filled. Validate on RHEL laptop + macOS.

---

### Sprint 2 — New Disk + Security Commands (Week 3–4)

| Task | Spec | Effort | File |
|---|---|---|---|
| `dsd disk` fast — filesystems, SMART summary, disk type | Spec 4 | ~3d | cmd/disk.go + collectors/disk.go (new) |
| `dsd disk` addendum — fuser busy check | Spec 4a | +0.5d | collectors/disk.go |
| `dsd disk` addendum — ZFS pool health (`zpool status -x`) | Spec 4b | +0.25d | collectors/disk.go |
| `dsd security` fast — SSH config, sudo, SUID, open ports | Spec 13 | ~3d | cmd/security.go + collectors/security.go (new) |

**Sprint 2 deliverable:** `dsd disk` and `dsd security` shipped fast.
Validate `dsd disk` on Proxmox (ZFS pools, LVM, HDD/SSD/NVMe mix).

---

### Sprint 3 — Docker + Kubernetes Full Build (Week 5–6)

| Task | Spec | Effort | File |
|---|---|---|---|
| `dsd docker` addendums 7a–7o (15 checks) | Specs 7a–7o | ~2.2d | cmd/docker.go + collectors/docker.go (extend) |
| `dsd k8s` fast extensions | Spec 23 fast | ~5d | cmd/k8s.go + collectors/k8s.go (extend) |
| `dsd k8s` addendums 23a–23g | Specs 23a–23g | ~0.8d | collectors/k8s.go (extend) |

**Sprint 3 deliverable:** Docker and k8s commands fully specced and shipped.
Docker: validate on RHEL laptop with real broken containers.
k8s: validate on k3s (already installed on RHEL laptop).

**Key implementation note for 23a–23g:**
All 4 addendums (23a, 23b, 23c, 23f) share ONE `kubectl get pods -A -o json` call.
Replace the existing `--no-headers` call with the JSON call. No extra API round-trips.

---

### Sprint 4 — Virtualisation Commands (Week 7–8)

| Task | Spec | Effort | File |
|---|---|---|---|
| `dsd pve` fast — node, VMs, storage, tasks, cluster | Spec 24 fast | ~2d | cmd/pve.go + collectors/pve.go (new) |
| `dsd pve` deep — PVEPerf, backup audit, bridge STP | Spec 24 deep | ~2d | collectors/pve.go (extend) |
| `dsd kvm` fast — virsh VM status, network, storage | Spec 15 | ~3d | cmd/kvm.go + collectors/kvm.go (new) |
| `dsd disk` deep — IO attribution, large dirs, LVM | Spec 4 deep | ~2d | collectors/disk.go (extend) |

**Sprint 4 deliverable:** Full virtualisation coverage shipped.
Validate `dsd pve` on Proxmox host. Validate `dsd kvm` on RHEL laptop.

---

## Key Design Decisions (Lock These In Before Coding)

### `dsd k8s` — Shared JSON call
```go
// ONE call replaces multiple --no-headers calls
out, err := k8sRun(ctx, bin, "get", "pods", "-A", "-o", "json")
// Then parse: deletionTimestamp (23a), initContainerStatuses (23b),
// lastState.terminated.message (23c), ownerReferences (23f)
```

### `dsd docker` — Socket API only, no docker CLI dependency
```go
// All checks via GET requests to Docker socket
// POST /v1.41/containers/{id}/json  → all inspect data
// GET /v1.41/events?since=X        → recent events (7e)
// Podman socket supported via same API
```

### `dsd pve` — pvesh with timeout
```go
// All data via pvesh REST API
// Wrap every call with 10s context timeout
// pvesh is always available on PVE nodes (/usr/bin/pvesh)
cmd := exec.CommandContext(ctx, "pvesh", "get",
    "/nodes/localhost/status", "--output-format", "json")
```

### `dsd disk` — ZFS gate (zero overhead on non-ZFS)
```go
// Gate 1: zpool binary exists
// Gate 2: at least one zfs mount in /proc/mounts
// If gate passes: zpool status -x (empty output = all pools healthy)
// Only parse full zpool status if -x produces output
```

### Bridge STP detection (Spec 24 deep)
```go
// Read /sys/class/net/<bridge>/bridge/stp_state
// 1 = STP enabled (causes ~30s boot delay) → WARN
// 0 = STP disabled → OK
```

---

## What Each Spec Contains

When you open `DashDiag_Gap_Specs.md` for a spec, you'll find:
- **Pain source** — why this matters to admins
- **What to add** — exact commands, file paths, data sources
- **Output example** — copy this as your target UX
- **JSON schema** — what `--json` must include
- **Acceptance criteria** — checklist to tick off before marking done

---

## Test Validation Targets

| Command | Primary test machine | Key scenario |
|---|---|---|
| `dsd services deep` | RHEL laptop | Mask a unit, check detection |
| `dsd disk` | Proxmox host | ZFS pool, LVM, HDD+SSD+NVMe |
| `dsd docker` | RHEL laptop | OOM-kill a container, check 7a/7e |
| `dsd k8s` | RHEL laptop (k3s) | CrashLoopBackOff pod, PVC Pending |
| `dsd pve` | Proxmox host | Run pveperf, check backup audit |
| `dsd kvm` | RHEL laptop | Paused VM, missing disk image |

---

## File Map

```
/Users/andreibeshkov/dev/dashdiag/
├── DashDiag_Gap_Specs.md     ← Full spec bible (51 items, ~58d)
├── BACKLOG.md                ← Sprint-ordered feature list
├── BUILD_KICKOFF.md          ← This file
├── DashDiag_Project_Guide.md ← Main project bible (merge gap specs at v49+)
├── cmd/
│   ├── docker.go             ← Extend with 7a–7o
│   ├── k8s.go                ← Extend with Spec 23
│   ├── pve.go                ← Create (Spec 24)
│   ├── kvm.go                ← Create (Spec 15)
│   └── disk.go               ← Create (Spec 4)
└── internal/collectors/
    ├── docker.go             ← Extend with 7a–7o checks
    ├── k8s.go                ← Extend with Spec 23 checks
    ├── pve.go                ← Create (Spec 24)
    ├── kvm.go                ← Create (Spec 15)
    └── disk.go               ← Create (Spec 4 + 4a + 4b)
```

---

## Monetisation Reminder

**First paying customer target: ~6 weeks from Sprint 1 start.**

Sprint 1–2 completes the "core Linux admin" story → enough for first outreach.
Sprint 3 adds Docker/k8s → unlocks the DevOps/SRE segment.
Sprint 4 adds Proxmox/KVM → unlocks home lab and SMB segment.

`dsd` is free. `dsd --deep` requires a licence key after the trial period.
The gap spec commands (docker, k8s, pve, kvm, disk) are all candidates for
the "Pro" tier that justifies the first paid conversation.
