# DashDiag — Claude Code Project Context

> All architecture rules, coding patterns, security rules, and testing rules
> are in `.cursorrules`. Claude Code reads both files. The rules there are
> NON-NEGOTIABLE. Read `.cursorrules` before writing any code.

---

## Current Phase: IMPLEMENTATION (Sessions 1–6 complete)

Research is complete. ~80 sources processed. Gap spec is saturated.
**DashDiag_Gap_Specs.md** is the single source of truth for what to build.
**BACKLOG.md** has the full sprint-ordered backlog with ✅ markers for completed items.

---

## What Ships (as of Session 6, commits 9822a57 + f1a8296)

```
dsd health       ✅ fast + deep (cgroup v2, sessions, k8s, docker wired in)
dsd health deep  ✅ per-core CPU, top procs, smaps_rollup, cgroup v2 slices
dsd net          ✅ fast + deep + dns subcommand
dsd net dns      ✅ resolv.conf audit, NM/resolved, live resolution test
dsd logs         ✅ severity summary, crash files, log source detection
dsd services     ✅ fast + deep (failed units, boot offenders, journal health)
dsd docker       ✅ crash-loop fixed, MTU check, netavark detection
dsd k8s          ✅ JSON API, events, OS-layer deep, wired into dsd health
dsd proc         ✅ smaps_rollup, FD map, socket conns, D-state guide
dsd cron         ✅ daemon, failures, quality, anacron staleness
dsd gpu          ✅ AMD amdgpu sysfs, NVIDIA nouveau detection
dsd security     ✅ sshd -T, AVC grouping, user audit, world-writable
dsd disk         ✅ SMART (Linux+macOS), ZFS, I/O rate, physical drives
```

**Do not rewrite or restructure these. Only extend them.**

---

## What Gets Built Next (Priority Order)

### Session 7 — Virtualisation (needs Proxmox hardware)
1. `dsd pve` — Proxmox VE node diagnostics (Spec 24, ~4d)
2. `dsd kvm` — KVM/libvirt diagnostics (Spec 15, ~3d)

### Session 8 — Networking deep
3. `dsd net deep` — NFS mount health (Spec 11, ~1.5d)
4. `dsd net deep` — BIND/named server health (Spec 16, ~1d)

### Session 9 — Package integrity
5. Package dependency integrity (Spec 12, ~0.5d)

---

## Key Implementation Notes

### Deploy pattern
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```
Binary goes to `/usr/local/bin/dsd` on 192.168.1.145 (RHEL 10.1 Legion).

### SMART parsing — NVMe field format
`smartctl -A` on NVMe outputs `"Temperature:  51 Celsius"` (with spaces, colon).
Parser uses `strings.Index(line, ":")` + `strings.Fields(val)[0]` to extract the
first token. Guard with `len(valFields) == 0` before indexing.

### macOS SMART — no smartctl needed
`diskutil info /dev/diskN` gives `SMART Status: Verified` for every internal disk.
`disk_darwin.go` uses this. No Homebrew dependency.

### k3s binary not in sudo PATH
k3s is at `/usr/local/bin/k3s`. `exec.LookPath("k3s")` fails under `sudo -n`.
Fix: `os.Stat("/usr/local/bin/k3s")` directly (done in k8s.go `K8sAvailable()`).

### ZFS gate — zero overhead on non-ZFS systems
```go
// Gate 1: zpool binary exists
// Gate 2: /proc/mounts has a "zfs" fstype entry
// Only runs collectZFSPools() when both true
```
`parseZFSSize()` lives in `internal/collectors/zfs.go` — don't redeclare in disk_linux.go.

### Build tag pattern for platform-specific collectors
```
disk_linux.go       → //go:build linux
disk_darwin.go      → //go:build darwin
disk_darwin_stub.go → //go:build darwin       (no-op for Linux-only methods)
disk_notlinux.go    → //go:build !linux && !darwin
```

### Docker socket detection under sudo
`DetectContainerSocket()` exported from `internal/collectors/docker.go`.
Checks `/run/podman/podman.sock` and `/var/run/docker.sock` directly.

### funlen limit = 90 statements
Split at logical section boundaries. Renderers: extract sub-functions per section.
Heuristics: extract `checkXxxNodes`, `checkXxxPodHealth` etc.

---

## Test Machine

| Fact | Value |
|---|---|
| IP | 192.168.1.145 |
| OS | RHEL 10.1 (Coughlan), kernel 6.12 |
| CPU | AMD Ryzen 7 5800H, 8c/16t |
| RAM | 16 GB DDR4 |
| Storage | 2× SK Hynix 1TB NVMe (nvme0n1, nvme1n1) |
| GPU | AMD Radeon (amdgpu) + NVIDIA RTX 3070 (nouveau) |
| k3s | v1.35.4 at `/usr/local/bin/k3s` |
| Podman | 5.6.0 at `/run/podman/podman.sock` |
| Go | 1.24.3 at `/home/andrei/go/bin/go` |
| smartctl | 7.4 at `/usr/sbin/smartctl` |

**MacBook (dev machine):**
- Apple M-series arm64, macOS, disk0 APPLE SSD AP0512R 500GB
- `diskutil info` → SMART: Verified, Protocol: Apple Fabric

---

## New Files Needed (Sessions 7–9)

```
cmd/pve.go                           Session 7
internal/collectors/pve_linux.go     Session 7
internal/models/pve.go               Session 7
cmd/kvm.go                           Session 7
internal/collectors/kvm_linux.go     Session 7
internal/models/kvm.go               Session 7
```

Follow the pattern of `disk_linux.go` + `disk_darwin.go` + `disk_notlinux.go`
when creating new platform-specific collectors.

---

## Gap Spec File Locations

```
DashDiag_Gap_Specs.md    ← 51 spec items, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Full feature backlog (sprint-ordered, ✅ for done)
```
