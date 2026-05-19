# DashDiag — Claude Code Project Context

> All architecture rules, coding patterns, security rules, and testing rules
> are in `.cursorrules`. Claude Code reads both files. The rules there are
> NON-NEGOTIABLE. Read `.cursorrules` before writing any code.

---

## Current Phase: IMPLEMENTATION (Sessions 1–5 complete)

Research is complete. ~80 sources processed. Gap spec is saturated.
**DashDiag_Gap_Specs.md** is the single source of truth for what to build.
**BACKLOG.md** has the full sprint-ordered backlog with ✅ markers for completed items.

---

## What Ships (as of Session 5, commit a248bd0)

```
dsd health       ✅ fast + deep (cgroup v2, sessions, k8s, docker wired in)
dsd health deep  ✅ per-core CPU, top procs, smaps_rollup, cgroup v2 slices
dsd net          ✅ fast + deep + dns subcommand
dsd net dns      ✅ resolv.conf audit, NM/resolved, live resolution test
dsd logs         ✅ fast + deep
dsd services     ✅ fast + deep (services deep: failed units, boot, journal)
dsd docker       ✅ crash-loop fixed, MTU check, netavark detection
dsd k8s          ✅ JSON API, events, PVCs, workloads, OS-layer deep
dsd proc         ✅ smaps_rollup, FD map, socket conns, D-state guide
dsd cron         ✅ daemon, failures, quality, anacron staleness
dsd gpu          ✅ AMD amdgpu sysfs, NVIDIA nouveau detection
dsd security     ✅ sshd -T, AVC grouping, user audit, world-writable
```

**Do not rewrite or restructure these. Only extend them.**

---

## What Gets Built Next (Priority Order)

### Session 6 — Logs + Disk
1. `dsd logs` — severity summary, crash files, /var/log/* scan (Spec 3, ~1.5d)
2. `dsd disk` — standalone: mounts, SMART, ZFS, fuser, LVM (Spec 4+4a+4b, ~2d)

### Session 7 — Virtualisation
3. `dsd pve` — Proxmox VE diagnostics (Spec 24, ~4d) — needs Proxmox hardware
4. `dsd kvm` — KVM/libvirt diagnostics (Spec 15, ~3d)

### Session 8 — Networking deep
5. `dsd net deep` — NFS mount health (Spec 11, ~1.5d)
6. `dsd net deep` — BIND/named server health (Spec 16, ~1d)

---

## Key Implementation Notes

### Deploy pattern (use this every time)
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```
Binary goes to `/usr/local/bin/dsd` on 192.168.1.145 (RHEL 10.1 Legion).

### k3s binary not in sudo PATH
k3s is at `/usr/local/bin/k3s`. `exec.LookPath("k3s")` fails under `sudo -n`
because sudo strips PATH to a secure subset that excludes `/usr/local/bin`.
Fix: use `os.Stat("/usr/local/bin/k3s")` directly (already done in k8s.go).

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
// Only parse full zpool status when -x produces output
```

### Docker socket detection under sudo
`DetectContainerSocket()` exported from `internal/collectors/docker.go`.
Checks `/run/podman/podman.sock` and `/var/run/docker.sock` directly.
Use this pattern for any container-gated check.

---

## Test Machine

| Fact | Value |
|---|---|
| IP | 192.168.1.145 |
| OS | RHEL 10.1 (Coughlan), kernel 6.12 |
| CPU | AMD Ryzen 7 5800H, 8c/16t |
| RAM | 16 GB DDR4 |
| Storage | 2× SK Hynix 1TB NVMe |
| GPU | AMD Radeon (amdgpu) + NVIDIA RTX 3070 (nouveau) |
| k3s | v1.35.4 at `/usr/local/bin/k3s` |
| Podman | 5.6.0 at `/run/podman/podman.sock` |
| Go | 1.24.3 at `/home/andrei/go/bin/go` |

---

## Gap Spec File Locations

```
DashDiag_Gap_Specs.md    ← 51 spec items, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Full feature backlog (sprint-ordered, ✅ for done)
```

---

## New Files Needed (Sessions 6–8)

```
cmd/disk.go                          Session 6
internal/collectors/disk_linux.go    Session 6
internal/collectors/disk_notlinux.go Session 6
internal/models/disk.go              Session 6
cmd/pve.go                           Session 7
internal/collectors/pve_linux.go     Session 7
internal/models/pve.go               Session 7
cmd/kvm.go                           Session 7
internal/collectors/kvm_linux.go     Session 7
internal/models/kvm.go               Session 7
```

Follow the pattern of `internal/collectors/proc_linux.go` + `proc_notlinux.go`
when creating new Linux-only collectors with cross-platform stubs.
