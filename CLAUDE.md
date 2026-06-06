# DashDiag — Claude Code Project Context

> All architecture rules, coding patterns, security rules, and testing rules
> are in `.cursorrules`. Claude Code reads both files. The rules there are
> NON-NEGOTIABLE. Read `.cursorrules` before writing any code.

---

## Current Phase: GTM UNBLOCKING (June 2026)

Sessions 1–12 complete. Bug fixes and NixOS validation complete.
**Next priority: landing page live at dashdiag.sh → first paying customer.**

> **Reality check (June 5, 2026):** the collector freeze below was NOT held.
> Between June 3 and June 5, PRs #11–#16 shipped new product surface anyway:
> `dsd fleet`, `dsd inventory`, `dsd update` self-updater, cloud-init health
> collector, `.deb`/`.rpm` packaging, and a Homebrew tap. These were judged
> "build-worthy / no-backend" items, but they did NOT advance the revenue path.
> **The three actual GTM blockers are still all PENDING** (register domain,
> wire email capture, deploy landing page). The freeze is hereby RESTATED: no
> further product features until the landing page is live and capturing emails.
> The domain is now registered (June 5). The remaining user action is creating
> the Formspree/Tally endpoint; the landing source lives in the separate repo
> `keyorixhq/dashdiag-landing`.

**June 3 (session 2) status:** repo is **public** (`github.com/keyorixhq/dashdiag`),
**v0.6.1 released** (4 binaries + `checksums.txt`), and the `install.sh` one-liner
is **live and verified working**. Remaining GTM: register dashdiag.sh, deploy the
landing page (now its own repo `keyorixhq/dashdiag-landing`), wire email capture.

**GTM checklist (do in order):**
1. ✅ DONE — Register `dashdiag.sh` (registered June 5, 2026; DNS → landing page after deploy)
2. ✅ DONE — repo public (`github.com/keyorixhq/dashdiag`)
3. ✅ DONE — GitHub release v0.6.1 (4 binaries + `checksums.txt`, install one-liner verified)
4. ⬜ **PENDING** — Wire email capture — search `STUB` in `index.html` (now in repo `keyorixhq/dashdiag-landing`), swap for Formspree/Tally endpoint (user creates endpoint → one-line swap)
5. ⬜ **PENDING** — Deploy landing page — repo `keyorixhq/dashdiag-landing` (Netlify deploy pending), DNS → dashdiag.sh

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
dsd cis          ✅ CIS/STIG compliance benchmark (CIS Ubuntu 22.04 L1 default).
                    66-rule registry (SSH 5.2.x, network 3.x, audit 4.x, auth/files 5-6.x);
                    --level 1|2, --fail-only, --stig (DISA STIG IDs), --json. Rule logic
                    unit-tested (internal/cis); validated live on Debian/AlmaLinux/openSUSE.
dsd disk         ✅ SMART (Linux+macOS), ZFS, I/O rate, physical drives,
                    LVM (VGs + thin pools + snapshots + RAID/mirror)
dsd kvm          ✅ VM/network/pool/disk error diagnostics (libvirt/QEMU)
dsd steamos      🟡 Steam Deck/SteamOS: device identity + Secure Boot (17a), RAUC A/B slots,
                    steamos-readonly, gamescope session, /var+/home, atomic-update-server reach,
                    Remote Play ports/firewall/AP-isolation (22A); --deep (proton/flatpak/bios).
                    Specs 17+17a+22A. Gated on platform.IsSteamOS, wired into dsd health.
dsd disk         🟡 +[SteamOS storage] (Spec 19): shader cache + offload bind mounts (gated).
                    btrfs root errors come from the generic btrfs collector; /var+/home from the
                    generic Filesystems list — not duplicated here.
dsd net          🟡 +SteamOS Wi-Fi (Spec 20+22B): backend (sole home), dual-band SSID conflict,
                    Steam CDN DNS, Remote Play link quality (band/channel/width/signal) — gated.
                    Note: SteamOS checks are consolidated to one home each (Wi-Fi→net, shader→disk,
                    btrfs→generic, update-server→steamos) — no duplicate insights in dsd health.
                    ✅ All SteamOS work (17/17a/19/20/22) on branch `steamos` VALIDATED against
                    real tooling on a SteamOS-spoofed Debian UEFI VM (pve01 VM 102): real rauc 1.13
                    JSON+text, mac80211_hwsim Wi-Fi, btrfs, nft, ss, efivar, Jupiter/ROG-Ally DMI.
                    Fixed an applyRAUCText bug (real rauc uses ○/⏺ glyphs + ANSI, not ASCII o/x).
                    Only Game-Mode gamescope state still needs a real Deck. See BACKLOG [STEAMOS-VALIDATION].
dsd timeline     ✅ unified incident timeline — journal+dmesg+load, dedup ×N; --since 1h/6h/24h
dsd tls          ✅ local cert file scan + remote endpoint expiry (--endpoint host:port,
                    --endpoints-file, --json); InsecureSkipVerify to read expired certs
dsd cve          ✅ per-CVE + --all advisory scan (dnf/apt/zypper/pacman), OVAL --oval-scan,
                    CISA KEV escalation (sidecar /var/lib/dsd/kev/), --json; `dsd cve info` sources
health --cve     ✅ folds CVE scan into health as live WARN(≥7.0)/CRIT(≥9.0 or KEV) insights
dsd fleet        ✅ run `dsd health` across many hosts over plain SSH; aggregated verdict
                    table; --hosts-file, --bin (scp deploy), --json. No backend (#15)
dsd inventory    ✅ CMDB-ingestable hardware/software export (JSON default, --csv, --out);
                    technical-facts layer only, assembled from existing collectors (#13)
dsd update       ✅ self-updater — GH releases API + sha256 verify + atomic replace;
                    --check/--yes; passive 24h version nudge in health footer (#14)
health cloud-init ✅ CloudInitCollector — `cloud-init status --format=json`; error→CRIT,
                    degraded→WARN; gated, never blocks (no --wait) (#11)
packaging        ✅ nfpm .deb/.rpm (scripts/build-packages.sh) + Homebrew tap
                    (keyorixhq/tap/dsd); both attached on tag push (#11, #12).
                    + AppImage (scripts/build-appimage.sh) — single-file, survives
                    SteamOS immutable-rootfs updates; x86_64+aarch64 attached on tag push.
                    Enables the SteamOS viral-channel install story (Guide §31)
```

**Do not rewrite or restructure these. Only extend them.**

---

## What Gets Built Next (Priority Order)

### Session 11 — First Paying Customer Path
1. ✅ DONE — `dsd pve` — Proxmox VE node diagnostics (Spec 24, commit ae9c4c4).
   Verified live on pve01: node overview, task errors, per-VM backup audit, bridges, `--json`.
2. ✅ DONE — **Correlation engine v1** — all 8 rules shipped (commits eaec50a, 04638ec, 6058936).
   `dsd timeline` + `dsd health deep` OOM kills + `dsd docker` container stops are wired.
3. ✅ DONE — **CVE exposure check** — `dsd health --cve` (CVSS ≥7.0 WARN, ≥9.0 CRIT) +
   CISA KEV escalation (sidecar catalog, no cloud registration)
4. **Hetzner Debian validation** — apt vs dnf, AppArmor denials, no SELinux.
   Largely covered by the reusable Debian 13 VM (VM 101 on pve01, validated Jun 4).

### Remaining docker addendums — ✅ ALL DONE
- ✅ Spec 7g — DNS trap: container DNS points to host systemd-resolved loop (commit 57754c2)
- ✅ Spec 7h — Docker socket file permissions / group membership diagnosis (commit 57754c2)
- ✅ Spec 7i — Architecture mismatch: ARM image on x86 host (commit 57754c2)
- ✅ Spec 7j — Swarm mode node health (commit b0d5c28)

---

## Key Implementation Notes

### Deploy pattern (use this every time)
```bash
make release
scp dist/dsd-linux-amd64 root@<ip>:/tmp/dsd   # <ip> = a guest from the Test Matrix below
ssh root@<ip> '/tmp/dsd health'
```
(The old `make deploy` to Legion at 192.168.1.145 is obsolete — Legion was wiped and
given away June 2026. Deploy to the pve01 guest matrix instead.)

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
