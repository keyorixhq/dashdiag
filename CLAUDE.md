# DashDiag — Claude Code Project Context

> All architecture rules, coding patterns, security rules, and testing rules
> are in `.cursorrules`. Claude Code reads both files. The rules there are
> NON-NEGOTIABLE. Read `.cursorrules` before writing any code.

---

## Current Phase: IMPLEMENTATION (Sessions 1–8 complete)

Research is complete. ~80 sources processed. Gap spec is saturated.
**DashDiag_Gap_Specs.md** is the single source of truth for what to build.
**BACKLOG.md** has the full sprint-ordered backlog with ✅ markers for completed items.

---

## What Ships (as of Session 8, commit d8351a9)

```
dsd health       ✅ fast + deep (cgroup v2, sessions, k8s, docker, kvm wired in)
dsd health deep  ✅ per-core CPU, top procs, smaps_rollup, cgroup v2 slices,
                    package integrity (dpkg/dnf check, missing libs)
dsd net          ✅ fast + deep + dns subcommand
dsd net dns      ✅ resolv.conf audit, NM/resolved, live resolution test
dsd net deep     ✅ + NFS mount health + BIND/named server health
dsd logs         ✅ severity summary, crash files, log source detection
dsd services     ✅ fast + deep (failed units, boot offenders, journal health)
dsd docker       ✅ crash-loop fixed, MTU check, netavark detection
dsd k8s          ✅ JSON API, events, OS-layer deep, wired into dsd health
dsd proc         ✅ smaps_rollup, FD map, socket conns, D-state guide
dsd cron         ✅ daemon, failures, quality, anacron staleness
dsd gpu          ✅ AMD amdgpu sysfs, NVIDIA nouveau detection
dsd security     ✅ sshd -T, AVC grouping, user audit, world-writable
dsd disk         ✅ SMART (Linux+macOS), ZFS, I/O rate, physical drives
dsd kvm          ✅ VM/network/pool/disk error diagnostics (libvirt/QEMU)
```

**Do not rewrite or restructure these. Only extend them.**

---

## What Gets Built Next (Priority Order)

### Session 9 — Proxmox (needs hardware)
1. `dsd pve` — Proxmox VE node diagnostics (Spec 24, ~4d) — **BLOCKED on Proxmox hardware**

### Unblocked alternatives
2. `dsd ssh` — SSH connection doctor (Spec 13, ~1.5d) — testable on Legion
3. `dsd timeline` — unified incident timeline (Spec 22, ~3d) — capstone feature
4. CVE exposure check — OVAL feed integration (~1 week)

---

## Key Implementation Notes

### Deploy pattern (use this every time)
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```
Binary goes to `/usr/local/bin/dsd` on 192.168.1.145 (RHEL 10.1 Legion).

### k3s binary not in sudo PATH
```go
// WRONG: exec.LookPath("k3s") — sudo strips /usr/local/bin from PATH
// RIGHT: os.Stat("/usr/local/bin/k3s") — absolute path check
```

### Gate pattern (dsd kvm, dsd k8s, docker)
```go
// Export a cheap binary-check function, call from cmd/health.go
func KVMAvailable() bool { /* virsh version --daemon exit 0 */ }
func K8sAvailable() bool { /* os.Stat("/usr/local/bin/k3s") */ }
```

### dsd net deep — multi-collector pattern
```go
// cmd/net.go runs NFSCollector + BINDCollector alongside NetworkDeepCollector
// Type-switch on result: *models.NFSInfo, *models.BINDInfo, *models.NetworkInfo
// nil return from collector = section absent (gate pattern)
```

### NFS non-blocking stale detection
```go
// NEVER: syscall.Statfs(mount) directly — hangs indefinitely on stale mount
// ALWAYS: goroutine + time.After(2s) select
go func() { err := syscall.Statfs(mount, &st); ch <- err }()
select { case <-ch: /* healthy */ case <-time.After(2s): /* STALE */ }
```

### BIND zone parser — skip hint/forward zones
```go
// hint and forward zones are not checkable with named-checkzone
// Watch for "type hint;" / "type forward;" inside zone block
// Follow "include" directives (depth-limited to 5 levels)
```

### funlen limit = 90 statements, cyclop = 30 branches
Renderers: split into Identity/State/Resources/Files/Connections sections.
Heuristics: split into sub-checks (checkK8sNodes, checkK8sPodHealth, etc).
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

---

## New Files Needed (Session 9+)

```
cmd/pve.go                           Session 9 (blocked)
internal/collectors/pve_linux.go     Session 9 (blocked)
internal/models/pve.go               Session 9 (blocked)
cmd/ssh.go                           Session 9 alternative
internal/collectors/ssh_linux.go     Session 9 alternative
internal/models/ssh_doctor.go        Session 9 alternative
```

Follow the pattern of `nfs_linux.go` + `nfs_notlinux.go` for new Linux-only
collectors that add sections to `dsd net deep` or similar commands.
