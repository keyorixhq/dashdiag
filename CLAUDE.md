# DashDiag — Claude Code Project Context

> All architecture rules, coding patterns, security rules, and testing rules
> are in `.cursorrules`. Claude Code reads both files. The rules there are
> NON-NEGOTIABLE. Read `.cursorrules` before writing any code.

---

## Current Phase: GTM UNBLOCKING (June 2026)

Sessions 1–12 complete. Bug fixes and NixOS validation complete.
**Next priority: landing page live at dashdiag.sh → first paying customer.**
Do NOT start new collectors or the distro-aware fix suggestions sprint until
the landing page is deployed and collecting emails.

**June 3 (session 2) status:** repo is **public** (`github.com/keyorixhq/dashdiag`),
**v0.6.1 released** (4 binaries + `checksums.txt`), and the `install.sh` one-liner
is **live and verified working**. Remaining GTM: register dashdiag.sh, deploy the
landing page (now its own repo `keyorixhq/dashdiag-landing`), wire email capture.

**GTM checklist (do in order):**
1. Register `dashdiag.sh` (~$35/yr, Namecheap, confirmed available)
2. ✅ DONE — repo public (`github.com/keyorixhq/dashdiag`)
3. ✅ DONE — GitHub release v0.6.1 (4 binaries + `checksums.txt`, install one-liner verified)
4. Wire email capture — search `STUB` in `index.html` (now in repo `keyorixhq/dashdiag-landing`), swap for Formspree/Tally endpoint
5. Deploy landing page — repo `keyorixhq/dashdiag-landing` (Netlify deploy pending), DNS → dashdiag.sh

---

## Dev Environment (June 2026)

**Primary machine: MacBook Air 15" (M3/M4, 24GB RAM)**
- Repo: `~/proj/dashdiag`
- Go: 1.26.4 arm64 (native Apple Silicon)
- SSH key: `~/.ssh/id_ed25519` with passphrase, stored in macOS Keychain
- Git identity: `Andrei Beshkov <andrey.beshkov@gmail.com>`
- Docker: OrbStack (not Colima, not Docker Desktop)
- Claude Code: v2.1.161

**Secondary machine: Proxmox host pve01 (192.168.10.20)**
- Repo: `/root/proj/dashdiag`
- Used for: scp deploy to LXC/VM test matrix, `dsd pve` development
- SSH key-based auth configured for `root@192.168.10.20` — no password needed for scp/ssh

**Deploy pattern (Mac → Linux guest):**
```bash
make release
scp dist/dsd-linux-amd64 root@<host>:/tmp/dsd
```

**Deploy pattern (Mac → Legion, legacy):**
Legion wiped and given away (June 2026) — this pattern is obsolete.

---

## What Ships (as of v0.6.1+, commit 1fb1004)

```
dsd health       ✅ fast + deep (cgroup v2, sessions, k8s, docker, kvm wired in)
dsd health deep  ✅ per-core CPU, top procs with cgroup scope labels,
                    smaps_rollup, cgroup v2 slices, package integrity
dsd net          ✅ fast + deep + dns subcommand
dsd net dns      ✅ resolv.conf audit, NM/resolved, live resolution test
dsd net deep     ✅ + NFS mount health + BIND/named server health + DNS resolver audit
dsd logs         ✅ severity summary, crash files, log source detection
dsd services     ✅ fast + deep (failed units, boot offenders, journal health)
dsd docker       ✅ exit code labels, events, secrets, root user, socket mount,
                    daemon health, log driver (--deep), IP forward, firewalld nftables,
                    Compose v1/v2 detection (Spec 7d)
dsd k8s          ✅ JSON API, events, OS-layer deep, wired into dsd health
dsd containerd   ✅ standalone containerd: socket, service state, version, namespace/container counts
platform.Profile ✅ distro normalization layer — Detect(), IsSteamOS, NetworkStack, SELinuxMode,
                    PackageManager, SyslogPath; wired into health + 3 collectors; unblocks SteamOS specs
dsd proc         ✅ smaps_rollup, FD map, socket conns, D-state guide
dsd cron         ✅ daemon, quality, anacron staleness
dsd gpu          ✅ AMD amdgpu sysfs (TDP/VRAM/clocks/util/Mesa, --deep), Intel i915 temp,
                    NVIDIA nvidia-smi fallback, --json; AMD path unit-tested, i915 live-verified
dsd security     ✅ sshd -T, AVC grouping + booleans + AppArmor, user audit,
                    /.autorelabel detection, PAM lockout;
                    --deep (was --suid): SUID scan; --save-baseline + --drift
dsd disk         ✅ SMART (Linux+macOS), ZFS, I/O rate, physical drives,
                    LVM (VGs + thin pools + snapshots + RAID/mirror)
dsd kvm          ✅ VM/network/pool/disk error diagnostics (libvirt/QEMU)
dsd timeline     ✅ unified incident timeline — journal+dmesg+load, dedup ×N; --since 1h/6h/24h
dsd tls          ✅ local cert file scan + remote endpoint expiry (--endpoint host:port,
                    --endpoints-file, --json); InsecureSkipVerify to read expired certs
dsd cve          ✅ per-CVE + --all advisory scan (dnf/apt/zypper/pacman), OVAL --oval-scan,
                    CISA KEV escalation (sidecar /var/lib/dsd/kev/), --json; `dsd cve info` sources
health --cve     ✅ folds CVE scan into health as live WARN(≥7.0)/CRIT(≥9.0 or KEV) insights
```

**Do not rewrite or restructure these. Only extend them.**

---

## What Gets Built Next (Priority Order)

### Session 11 — First Paying Customer Path
1. `dsd pve` — Proxmox VE node diagnostics (Spec 24, ~4d) — **BLOCKED: needs Proxmox hardware**
2. **Correlation engine v1** — wire the "20:00 overnight cluster" memory-pressure cascade rule
   Link: `dsd timeline` + `dsd health deep` OOM kills + `dsd docker` container stops
3. ✅ DONE — **CVE exposure check** — `dsd health --cve` (CVSS ≥7.0 WARN, ≥9.0 CRIT) +
   CISA KEV escalation (sidecar catalog, no cloud registration)
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

### PVE service port list — single source of truth
The PVE service port set `{8006, 3128, 111}` lives in one place:
`analysis.IsPVEServicePort` (`internal/analysis/heuristics.go`). `cmd/security.go`
consumes it; `security_linux.go` only flags the host via `IsPVEHost()`. Do not
re-inline the port set — extend the exported helper instead.

---

## Test Matrix

**Legion (RHEL 10.1) — wiped and given away June 2026. Replaced by AlmaLinux LXC.**

| CT/VM | Hostname | IP | OS | Status |
|---|---|---|---|---|
| CT 202 | ubuntu24-lxc | 192.168.10.10 | Ubuntu 24.04 LTS | running |
| CT 213 | almalinux9-lxc | 192.168.10.8 | AlmaLinux 9.4 (RHEL family) | running |
| VM 212 | nixos-25-05 | 192.168.10.11 | NixOS 25.05 (Warbler) | running |
| VM 214 | opensuse16-btrfs | 192.168.10.56 | openSUSE Leap 16 — XFS root + 4GB btrfs /dev/sdb at /mnt/btrfs-test | running |
| PVE base | pve01 | 192.168.10.20 | Debian 13 / PVE 9.1.1 | always on |

**Stopped (start with `pct start <id>` on pve01):**
CT 200 almalinux-lxc, CT 201 debian13-lxc, CT 203 rocky10-lxc, CT 204 opensuse16-lxc, VM 100 ubuntu24-min-vm

**Deploy to any guest:**
```bash
scp dist/dsd-linux-amd64 root@<ip>:/tmp/dsd
ssh root@<ip> '/tmp/dsd health'
```

---

## Gap Spec File Locations

```
DashDiag_Gap_Specs.md    ← 51 spec items, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Full feature backlog (sprint-ordered, ✅ for done)
```
