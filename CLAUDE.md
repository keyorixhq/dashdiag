# DashDiag — Claude Code Project Context

> All architecture rules, coding patterns, security rules, and testing rules
> are in `.cursorrules`. Claude Code reads both files. The rules there are
> NON-NEGOTIABLE. Read `.cursorrules` before writing any code.

---

## Current Phase: IMPLEMENTATION (Sessions 1–10 complete)

Research is complete. ~80 sources processed. Gap spec is saturated.
**DashDiag_Gap_Specs.md** is the single source of truth for what to build.
**BACKLOG.md** has the full sprint-ordered backlog with ✅ markers for completed items.

---

## What Ships (as of Session 10, commit 67ff3a7)

```
dsd health       ✅ fast + deep (cgroup v2, sessions, k8s, docker, kvm wired in)
dsd health deep  ✅ per-core CPU, top procs with cgroup scope labels,
                    smaps_rollup, cgroup v2 slices, package integrity
dsd net          ✅ fast + deep + dns subcommand
dsd net dns      ✅ resolv.conf audit, NM/resolved, live resolution test
dsd net deep     ✅ + NFS mount health + BIND/named server health
dsd logs         ✅ severity summary, crash files, log source detection
dsd services     ✅ fast + deep (failed units, boot offenders, journal health)
dsd docker       ✅ exit code labels, events, secrets, root user, socket mount,
                    daemon health, log driver (--deep), IP forward, firewalld nftables
dsd k8s          ✅ JSON API, events, OS-layer deep, wired into dsd health
dsd proc         ✅ smaps_rollup, FD map, socket conns, D-state guide
dsd cron         ✅ daemon, quality, anacron staleness
dsd gpu          ✅ AMD amdgpu sysfs, NVIDIA nouveau detection
dsd security     ✅ sshd -T, AVC grouping + booleans + AppArmor, user audit,
                    /.autorelabel detection, PAM lockout
dsd disk         ✅ SMART (Linux+macOS), ZFS, I/O rate, physical drives,
                    LVM (VGs + thin pools + snapshots + RAID/mirror)
dsd kvm          ✅ VM/network/pool/disk error diagnostics (libvirt/QEMU)
dsd timeline     ✅ unified incident timeline — journal+dmesg+load, dedup ×N
```

**Do not rewrite or restructure these. Only extend them.**

---

## What Gets Built Next (Priority Order)

### Session 11 — First Paying Customer Path
1. `dsd pve` — Proxmox VE node diagnostics (Spec 24, ~4d) — **BLOCKED: needs Proxmox hardware**
2. **Correlation engine v1** — wire the "20:00 overnight cluster" memory-pressure cascade rule
   Link: `dsd timeline` + `dsd health deep` OOM kills + `dsd docker` container stops
3. **CVE exposure check** — OVAL feed integration, CVSS ≥7.0 WARN, ≥9.0 CRIT (~1 week)
4. **Hetzner Debian validation** — apt vs dnf, AppArmor denials, no SELinux

### Remaining docker addendums (minor)
- Spec 7g — DNS trap: container DNS points to host systemd-resolved loop
- Spec 7h — Docker socket file permissions (should be 660, not 666)
- Spec 7i — Architecture mismatch: ARM image on x86 host (or vice versa)
- Spec 7j — Swarm mode node health

---

## Key Implementation Notes

### Deploy pattern (use this every time)
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```
Binary: `/usr/local/bin/dsd` on 192.168.1.145 (RHEL 10.1 Legion).

### Critical cross-compile pattern
```bash
go build ./...                                         # macOS arm64 (native)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ...   # Linux amd64
# make deploy does both — always fix both platforms
```
File stubs required for Linux-only features: `foo_notlinux.go` (`//go:build !linux`)
Also need darwin stubs if macOS build calls Linux functions: `foo_linux_darwin_stub.go`

### Gate pattern (KVM, K8s, Docker, BIND, NFS)
```go
// Export cheap binary-check, call from cmd/health.go or cmd/net.go
func KVMAvailable() bool { /* virsh version --daemon exit 0 */ }
func K8sAvailable() bool { /* os.Stat("/usr/local/bin/k3s") */ }
```
Nil return from collector = section absent (zero noise on non-relevant hosts).

### dsd net deep multi-collector pattern
```go
// NFSCollector + BINDCollector alongside NetworkDeepCollector
// type-switch on result: *models.NFSInfo, *models.BINDInfo, *models.NetworkInfo
// nil = section absent (gate pattern — service not running)
```

### NFS non-blocking stale detection (MUST USE THIS PATTERN)
```go
go func() { err := syscall.Statfs(mount, &st); ch <- err }()
select {
case <-ch:                     // healthy
case <-time.After(2*time.Second): // STALE — never blocks caller
}
```

### Timeline deduplication
```go
// Same unit + level + msg[:40] within same 60-second window → Count++
// filterTopEvents: keep all CRITs first, then most recent WARNs to fill cap
```

### cgroup scope labels
```go
// cgroupScope(pid): reads /proc/<pid>/cgroup, calls parseCgroupPath()
// parseCgroupPath: "0::/system.slice/k3s.service" → "system:k3s"
// libpod-<id>.scope → "container:<id12>"; /kubepods/ → "k8s"; / → "kernel"
```

### funlen limit = 90 statements, cyclop = 30 branches
Renderers: split into Identity/State/Resources/Files/Connections sections.
Heuristics: split into sub-checks (checkDockerContainers/Resources/Security etc).
`buildHealthCollectors` uses `//nolint:funlen,cyclop` — justified as flat registry.

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
| libvirt | 11.10.0, QEMU 10.1.0, test-vm running |
| BIND | 9.18.33 at `/usr/sbin/named`, 5 zones |
| NFS | `/mnt/nfs_test` → `127.0.0.1:/tmp/nfs_export` |

---

## Gap Spec File Locations

```
DashDiag_Gap_Specs.md    ← 51 spec items, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Full feature backlog (sprint-ordered, ✅ for done)
```
