# Work Queue — Open items by subsystem

Forward-looking index. BUGS.md stays the per-platform discovery log; this file
groups everything *open* by shared code surface + shared test target, so one
branch closes one class with one deploy/validate cycle. Demand-gated items are
listed for visibility only — grouping here is NOT a build trigger
(COMPANY_PRINCIPLES Principle 3, BACKLOG.md hard rule).

Status legend: **READY** (validated bug, build anytime) · **BLOCKED** (needs
hardware/decision) · **GATED** (demand-gated, build only on pull).

---

## ZC. k8s OS-layer kubelet/containerd detection k3s-only — ✅ DONE (2026-07-01)

Beyond-k3s OS-layer hardening pass (`dsd k8s --deep`) on the running rigs. Found + fixed
**BUG-096**: `collectK8sOSLayer` probed only kubelet/k3s units + the k3s containerd socket, so
`kubelet_active`/`containerd_active` were **false on healthy RKE2/k0s/MicroK8s** (each embeds
the kubelet under a distinct unit — `rke2-server`/`k0scontroller`/`snap.microk8s.daemon-kubelite`
— and containerd under a distinct socket). LOW impact (fields are `--json`-only, no verdict
consumes them yet — no false CRIT/OK), fixed so the data is correct. Generalized the unit list
+ a bundled-containerd-socket helper (`k8sBundledContainerdSockPresent`, unit-tested). Verified
live: both flags TRUE on RKE2 v1.35.6 / k0s v1.36.2 / MicroK8s v1.35.5. Unit/socket names in
memories `rke2-`/`k0s-`/`microk8s-validation-vm`.

---

## ZB. k0s validation + dsd blind to k0s clusters — ✅ DONE (2026-07-01)

Third "beyond k3s" target: real **k0s** v1.36.2 (Mirantis single-binary k8s) on **pve01
VM 111 `k0s-test`** (Debian 13, 192.168.10.53). Found + fixed **BUG-095**: k0s ships only
`/usr/local/bin/k0s` (no standalone kubectl; wraps it as `k0s kubectl`), which `k8sDetectBin`
didn't know → `K8sAvailable()` false → the entire K8s collector skipped → **no K8s section
at all** on a running control plane (a silent false-negative). Fix adds k0s to `k8sDetectBin`
(→ `k0s kubectl`) and `k8sDistribution` (`/var/lib/k0s` marker, before kubeadm since k0s
also writes /var/lib/kubelet/config.yaml). Detection tests added. Verified live (node Ready,
pods healthy, distribution=k0s, no EtcdIsVoter false-CRIT, honest non-root). Capture
`k0s-debian-20260701.tar.gz`. Memory `k0s-validation-vm`.

---

## ZA. kubeadm validation + `sudo dsd` can't reach the API — ✅ DONE (2026-07-01)

Second "beyond k3s" target: real **kubeadm** v1.31 (canonical reference, static-pod
control plane, flannel CNI) on **pve01 VM 109 `kubeadm-test`** (Debian 13, 192.168.10.52).
Confirmed BUG-093 doesn't over-fire (no `EtcdIsVoter` on kubeadm) and dsd honestly flagged
a genuinely-degraded coredns. Found + fixed **BUG-094**: `k8sDetectBin` had kubeconfig
detection for k3s/RKE2 but not kubeadm's **`/etc/kubernetes/admin.conf`**, so `sudo dsd
k8s`/`health` ran bare kubectl → localhost:8080 → "API unreachable" on a healthy cluster
(non-root via `~/.kube/config` worked — inverted privilege). Fix appends
`--kubeconfig=/etc/kubernetes/admin.conf` for plain kubectl, gated to root with no
kubeconfig of its own (non-root path untouched). Pure helper + table test
`kubeadm_kubeconfig_test.go`; capture `kubeadm-debian-20260701.tar.gz`. Memory
`kubeadm-validation-vm`. (Trixie gotcha: k8s apt repo's v3 signature is rejected by sqv →
`[trusted=yes]`; conntrack/socat needed for kubeadm preflight.)

---

## Z. RKE2 "beyond k3s" validation + `EtcdIsVoter` false-CRIT — ✅ DONE (2026-07-01)

First live validation of the k8s OS-layer on a real **RKE2** cluster (RKE2 detection
#667 + Rancher mgmt-plane check #668 were fixture-only). Single-node RKE2 v1.35.6 on
**pve01 VM 108 `rke2-test`** (Debian 13 cloud-init, 192.168.10.51). dsd auto-found the
RKE2 kubeconfig, read nodes/pods, k8s-aware sysctl checks correct, Rancher check
correctly silent (RKE2 ≠ Rancher). Found + fixed **BUG-093**: `checkK8sNodes`
(`heuristics_virt.go`) blanket-CRIT'd any node condition that was `True` except `Ready`,
so RKE2/k3s-etcd's **`EtcdIsVoter=True`** (which means *healthy* etcd voter) false-CRIT'd
every etcd control-plane node. Fix = allowlist the standard problem conditions
(MemoryPressure/DiskPressure/PIDPressure/NetworkUnavailable); never assume an unknown
condition is bad-when-True. Default-sqlite k3s has no etcd conditions → only "beyond
k3s" exposed it. Test `k8s_node_conditions_test.go`; capture `rke2-debian-20260701.tar.gz`.
Memory `rke2-validation-vm`. (kubeadm remains a possible follow-up.)

---

## Y. Host service collectors detect containerized processes — ✅ DONE (2026-07-01)

Validated the minimal-footprint "Docker host, no systemd" use case on **pve01 VM 106
`alpine-docker`** (Alpine 3.22 OpenRC/musl + Docker). Core path clean (OpenRC hints,
Docker folded into health, honest non-root). Found + fixed **BUG-092**: host service
collectors that detect via a `/proc/<pid>/comm` scan (`procCommRunning` → Nginx/Apache/
HAProxy; `anyProcessNamed` → BIND, + host daemons) matched **containerized** processes
visible in the host PID namespace and ran host-level checks against them (a misleading
`Nginx INFO "needs root"` here; a wrong host verdict on another service). Choke-point
fix: both scanners skip a match whose cgroup says it's a container, via a shared
`pidIsContainerizedIn` reusing `parseCgroupPath`. Distro-agnostic, host daemons
unaffected, unreadable-cgroup→host. Test `containerized_proc_linux_test.go`; capture
`alpine-docker-20260701.tar.gz`. Memory `alpine-docker-validation-vm`.

---

## X. NixOS full validation + `/nix/store` ro-bind false-WARN — ✅ DONE (2026-06-30)

First proper SSH-driven two-pass (root + non-root) + capture on real NixOS 25.05
(prior NixOS coverage was the `nixosifyHints` path + a console-only VM, never a deep
pass). Fresh scripted install (live ISO → `nixos-install` with SSH + pve01 key in
`configuration.nix`) on **pve01 VM 212 `nixos-test`** (192.168.10.47). Distro handling
was already solid — NixOS detected, all remedy hints route through `nixosifyHints`
(`…configuration.nix; nixos-rebuild switch`). One false-alarm found + fixed:

**BUG-091 — `/nix/store` ro bind WARNed as an I/O-error remount** (fixed #673). NixOS
binds `/nix/store` read-only off the rw root for immutability; `checkDisk` only
suppressed the ro-remount WARN for `ImmutableRootFS` (ostree/transactional/SteamOS),
which NixOS isn't. Fix is distro-agnostic (sibling to §K): a ro mount whose backing
**device is also mounted rw elsewhere** is an intentional ro bind (a kernel error
remount flips the whole device → `/` would be ro too), so it's suppressed; a ro mount
of a device not mounted rw anywhere still WARNs. `heuristics.go checkDisk` + real-bytes
unit test `nixos_nix_store_ro_test.go`. Capture
`~/proj/dashdiag-captures/nixos-2505-20260630.tar.gz` replays the bug pre-fix, clean
post-fix. Memory `nixos-validation-vm`.

---

## R. Oracle Linux real-VMware validation + RHEL-family deep checks — ✅ DONE (2026-06-29)

Clean two-pass validation of `dsd` on OL 9.8 (RHCK) and OL 10.1 (UEK) guests on real
VMware vCloud Director. Verdicts honest throughout. Three remediation-/message-accuracy
fixes + one guard, plus a gap-analysis that shipped five new RHEL/Oracle deep checks.

| Item | Surface | Result |
|---|---|---|
| BUG-084 — CIS auditd hint hardcoded Debian path/cmd on RHEL | `internal/cis` (rules + remediation) | fix #649 + source-scan guard #650 |
| BUG-085 — Drives "running unprivileged" when root on a virtual disk | `nvme_linux.go` + `heuristics_storage.go` | fix #651 (record `SmartUnreadReason`) |
| BUG-086 — SELinux "mode unreadable → re-run as root" (privilege won't help) | `heuristics_system.go` | fix #652 (AppArmor asymmetry pinned) |
| 5 new maintenance checks: Kdump / Tuned / Kernel-reboot / Ksplice / ServiceRestart | new `maintenance_linux.go` + `heuristics_maintenance.go` | feat #653 (2 live catches: tuned, stale-libs) |
| BUG-087 — #653 cross-distro quasi-false-OK (container, OL `kernel-uek-core`, SUSE `kernel-default`) | `maintenance_linux.go` | fix #655 (found running #653 on pve Alma-LXC + OL-UEK VM 121) |

Both OL guests fully captured (`~/proj/dashdiag-captures/oraclelinux{9,10}-vmware-vcd-full-*`).
vCD OVAs fixed + staged (`~/proj/dashdiag-ova/`; OL10 needs x86-64-v3 EVC). Memory:
`oracle-linux9-uek-validation`. **No open follow-ups** (Ksplice live-validation gated on
a Ksplice box; `needs-restarting`-via-dnf-utils deferred — native /proc scan used).

## A. Fix-hint platform correctness — ✅ DONE (#218, 2026-06-13)

All four items shipped in #218 and validated live (macOS native + Alpine/OpenRC
CT210): the platform-aware hint helper, the audit of direct-print remedy lines
(`dsd docker`/`cron`/`kvm`/`proc` + entropy correlation → `analysis.PlatformServiceCmd`),
and the idle-timeout-on-no-sshd gate. Left below for history.

Diagnosis is platform-correct; the remedy text is not. One class, one branch.

| Item | Surface | Test target |
|---|---|---|
| BUG-053 — `ss -tlnp` hint on macOS | hardening hints, heuristics.go | macOS native build |
| BUG-054 — `systemctl`/journald hints on Alpine/OpenRC | hardening + logs hints | Alpine CT210 |
| Audit: all hardcoded `ss` / `systemctl` / `/etc/systemd/*` hint strings | repo-wide grep of hint text | n/a (code review) |
| Minor: "SSH idle timeout not set" INFO on hosts with no sshd | hardening check gate | Alpine CT210 |

Shared work: a platform-aware hint helper (GOOS + init-system branch — init
detection already exists from the Alpine hardening pass). Fix the helper once,
route all hints through it, validate on macOS + CT210 in one pass.

**Follow-up — ✅ DONE (#611, 2026-06-28):** Gentoo/Portage sub-case. The
*package-install* fix hints (`apt/dnf/zypper install …`) still named the wrong
tool on Gentoo — they hardcode apt/dnf/zypper across ~12 sites and never emit
`emerge`. Added a host-gated `gentooifyHints` rewrite (mirrors `nixosifyHints`)
turning any install hint into `to fix (Gentoo): emerge <pkg>` (trailing
`&& <service-enable>` preserved), gated on `/etc/os-release ID=gentoo`. Found
live on the first Gentoo-on-real-VMware validation (BUGS.md BUG-073). Out of
scope: the `dsd gpu`/`dsd kvm` printf hints (separate surface).

**Follow-up — ✅ DONE (#644/#646/#647, 2026-06-29):** completed the BUG-054 class
across every non-systemd init. Init detection now recognizes **sysvinit** (Devuan)
and **runit** (Void) via PID1 identity (`classifyInit`/`/proc/1/comm`), not just
systemd+openrc — with the runit-package-on-sysvinit trap guarded. The adapter
covers openrc/sysvinit/runit (`serviceCmd`) and the previously-missed `systemctl
status` / `timedatectl` / `journalctl` inspect forms + embedded `&& systemctl
restart` tails, plus pacman/apk install hints (#644). The Alpine CI smoke is now a
genuine OpenRC surface (`apk add openrc`) and **asserts no leaked
systemctl/timedatectl/journalctl in hints** (#647) — the systemic guard for this
recurring (cosmetic) class. Found live on Artix (OpenRC) + Devuan (sysvinit),
BUGS.md BUG-083.

**Live-confirmed on real Void (runit), 2026-06-30:** the `runit` path was previously
only reasoned-about via Devuan's runit-package-on-sysvinit *trap* (runit pkg present
but sysvinit is PID1); Void is the first guest where **runit is actually PID1**. Did a
full scratch install (live ISO → scripted `xbps` chroot) onto **pve01 VM 105
`void-test`** (192.168.10.46) and ran the two-pass (root + non-root): **CLEAN, no
false-OK**. Remedy hints correctly emit `sv status chronyd` / `sv restart sshd` (runit),
no leaked systemd. root vs non-root differ only on Firewall (WARN→INFO) and OOM
(OK→INFO) — both degrade honestly toward INFO. Hermetic capture replays faithfully at
`~/proj/dashdiag-captures/void-runit-20260630.tar.gz`. Rig is now in the CLAUDE.md test
matrix; memory `void-linux-validation-vm`. No code change — the #644/#646 init work
already handled runit; this closes the "runit-as-PID1 never tested on real Void" gap.

---

## B. ARM real-hardware validation — BLOCKED (needs aarch64 server)

Software pass done (2026-06-10); Graviton2 confirmed CPU id + health clean.
Container-unverifiable paths remain (BUGS.md ARM section, PLATFORM_COVERAGE.md):

1. Thermal — /sys/class/hwmon SoC sensors
2. DMI/SMBIOS — real system product name (`dsd inventory`)
3. SMART on real NVMe/SAS; EDAC/ECC; IPMI/BMC
4. cpufreq governors / per-core scaling on many-core Ampere
5. Ampere SoC implementer id (0x41 vs 0xc0) — pin a fixture from real Altra

Unblock paths: offered Ampere Altra box, Oracle always-free Ampere, or RPi
(partial — covers thermal/cpufreq, not IPMI/EDAC). One SSH session closes the
whole class; keep as a single validation checklist, not five tasks.

---

## C. Cloud-depth collectors — GATED (no cloud customer yet)

Fully specced in BACKLOG.md (AWS Nitro core ~5–6 checks, Azure Hyper-V core
~5–7, full-coverage tiers beyond). Do not build from this index. When a
customer pulls a specific check, build that check only; the customer reveals
which of the core list matters next. Basic cloud *detection* is already
validated (AWS + Azure captures, NVMe-timeout insight).

---

## D. Deferred architecture / features — BLOCKED on decision or demand

| Item | Ref | Gate |
|---|---|---|
| state.Store + JSONL storage (drift / history) | Gap Spec 9, ADR-0001 | BUILT — `internal/store/` (JSONLStore + Prune + DiffChecks + ReadAll); `dsd health --persist` appends + auto-prunes to 365/host; `dsd history`; `dsd diff --last` (#840 + #842 + #843) |
| platform.Profile | Spec 8 | Architectural, deferred |
| `dsd capture --cve`, `--timeline` | session notes | Demand |
| containerd standalone detection | session notes | Demand, low priority |
| `--share`/`--push` backend (sanitization lives here, not in capture) | ADR-0002 D6, SHARE_DESIGN.md | Pilot/demand |

---

## E. Recurring audit plays (not tasks — repeatable sweeps)

These found BUG-040–052; re-run after any collector/heuristic change:

1. **False-OK sweep** — "couldn't verify" must never render as OK/green.
   7 grep-able anti-patterns in agent memory `false-ok-bug-class`. **Now partially
   automated:** the non-root subclass (a privileged tool degrading to a false
   OK/CRIT unprivileged — BUG-064/066/067/070) is CI-guarded by the **non-root
   verdict invariant** job (#527, `scripts/check-nonroot-invariant.sh`): runs
   `dsd health` root + non-root and fails if any check escalates non-root. Still
   re-run the manual sweep for the root-path false-OKs it can't see.
2. **Stale-signal recency gate** — cumulative counters (NRestarts, pstore)
   reported as current. Ask "where else?" — BUG-047/049 hid one file away.
3. **Sibling divergence diff** — same fact, two code paths, two verdicts
   (BUG-050 `cmd/disk.go` vs health thresholds). Diff cmd/* against analysis/.
   **Now CI-guarded:** the deterministic **cmd↔health consistency** test
   (#528/#530, `cmd/cmd_health_consistency_test.go`) pins every standalone
   command's verdict (gpu/kvm/docker/net/k8s/security) to its `dsd health`
   counterpart on the same model — it's what surfaced + fixed BUG-072 (`dsd
   security` undercounting SSH hardening). `dsd security` now derives its verdict
   from `checkSecurity` directly (#532), so that pair can't drift by construction.
4. **Zero-vs-unreported ambiguity** — a numeric `0` for "attribute/sensor not
   exposed" renders identically to a measured `0`. Distinct from the false-OK
   sweep (#1): here the *verdict* is usually correct, but the displayed/JSON
   value is ambiguous. Lineage: the GPU all-zero false-OK (§F, #c784f68) was the
   verdict-breaking end of this; the cosmetic end is benign-but-misleading.
   Observed 2026-06-16 on pve01 (row 20): the LiteOn SSD exposes no SMART attr
   194/9, so `dsd hardware --json` shows `temp_c:0, power_on_h:0` — accurate
   ("not reported"), verdict correct (`SMART: PASSED` is driven by the health
   bit, not the zeros), but a consumer can't tell 0 from unsupported. **Not a bug
   to blind-fix:** the honest representation (null / a `supported` flag / omit)
   changes the `--json` shape, which is the **frozen 1.0 contract** — needs a
   deliberate schema decision, not a patch. Audit scope when picked up: temp_c,
   power_on_h, wear_pct, reallocated/pending across drives; CPU/GPU temps; any
   sensor field that can legitimately be absent. Low priority. **2026-06-18
   escalation:** the VMware virtual NVMe (§L) is the verdict-breaking end of this
   class re-surfacing — when the read returns *implausible* values rather than
   absent ones, the zeros (non-root) or the garbage (root) drive a false CRIT.
   §E.4's "honest representation needs a schema decision" still holds for the
   benign cosmetic case; §L is the not-benign case and is READY to fix now.
5. **Non-systemd / musl assumptions** — collectors that shell `systemctl`/
   `journalctl` (or assume glibc tooling) mis-verdict or crash on OpenRC/busybox/
   musl: BUG-051 (DBus/journald phantom warnings), BUG-054 (systemctl fix-hints on
   Alpine), BUG-071 (OOM `dmesg --time-format` rejected by busybox dmesg). **Now
   CI-guarded:** the `alpine-musl-smoke` job (#551, `scripts/alpine-smoke.sh`) runs
   `dsd health` in `alpine:latest` and asserts no panic / valid JSON / no non-root
   escalation — the surface every other CI job (systemd+glibc) never touched. When
   adding a collector that calls a systemd/glibc tool, confirm the busybox/OpenRC
   fallback and let this job exercise it.

---

## F. GPU sensor-read false-OK — ✅ DONE (#c784f68, 2026-06-16)

Closed by real-hardware validation on the new Ubuntu-on-MacBookAir4,2 node
(192.168.10.7): Intel HD 3000 / i915 exposes no hwmon temp by design, and
`dsd gpu` was rendering "✅ GPU healthy. Checks passed" for a GPU whose
temp/util/mem/power all read 0 — asserting health it never measured. The new
node was exactly the GPU observation this entry was BLOCKED waiting for (it
needed *any* real iGPU with all-zero sensors, not specifically AMD). Fix took
the narrow path predicted below: `gpuSummaryLine` now reports "GPU detected — no
health metrics exposed; health not verified" (INFO) when EVERY device exposed
zero metrics; a GPU with any real metric still summarizes healthy. Left below
for history.

A 2026-06-13 false-OK sweep verified a real path: a detected AMD/Intel GPU whose
sysfs sensors all read 0 (temperature never read) still renders `dsd gpu` →
"✅ GPU healthy. Checks passed" and emits no health insight (`collectAMDGPUs`/
`collectIntelGPUs` always append the device; `checkGPU` only skips on `len==0`;
every threshold no-ops on 0; `gpuSummaryLine` default asserts "Checks passed").

**Not blind-fixed** — the obvious fix (per-device INFO "temperature not readable")
is noisy on the many normal Intel iGPUs that don't expose hwmon temp by design, and
there's no clean sysfs signal to tell "sensor broken" (rare, real) from "GPU exposes
no temp" (common, fine). Unlike drives (BUG-048: `/sys/class/nvme` exists without
nvme-cli = clean signal), GPU has none.

| Item | Surface | Test target |
|---|---|---|
| Confirm a healthy AMD GPU actually reads temp (expected yes) | gpu_linux.go | ✅ DONE 2026-06-18 — validated on real AMD Cezanne (see note) |
| If a clean "read nothing" signal exists → narrow guard: don't claim "Checks passed" when no device had a readable temp | cmd/gpu.go gpuSummaryLine + checkGPU | ✅ DONE (#383 — guard in cmd + health; metric-less device → INFO) |

Unblock: ~~one session on the AMD laptop~~ — CLOSED 2026-06-18. Agent memory: `gpu-allzero-falseok-deferred`.

**2026-06-17 attempt — did NOT close this.** Ran on a real AMD Cezanne APU
(PLATFORM_COVERAGE row 21) expecting to confirm a healthy AMD GPU reads temp. It
couldn't: the host was a **live USB booted with `nomodeset`**, so `amdgpu` loaded
but never initialized the device — every telemetry node (gpu_busy_percent, VRAM,
hwmon temp) was absent and `dsd` correctly reported no GPU check. **Lesson for the
next attempt: a live USB / `nomodeset` boot cannot test the GPU path.** Need a
host where amdgpu fully binds the card — a *persistent* install (drop `nomodeset`)
or a discrete-GPU box. Friend's Proxmox host is a candidate IF it has an
amdgpu-bound card.

**2026-06-18 — CLOSED. Validated on real AMD Cezanne silicon.** Rebooted the same
laptop's live USB WITHOUT `nomodeset` → amdgpu fully bound the Radeon Vega (Cezanne,
`/sys/class/drm/card1`, driver in use `amdgpu`). `dsd gpu` read and parsed the real
sysfs correctly: edge temp 30°C, VRAM 0.2/0.5 GB (47%, `[shared APU memory]`),
power 2W, clock 400/1800 MHz (22%), util 0%, **IsAPU=true** (GTT 7.5 GB present) so
the VRAM-pressure check is correctly suppressed. The #383 metric-less guard
correctly did NOT trip (real metrics present → "GPU healthy. Checks passed" is here
legitimate, not the false-OK). Captured (`dsd capture --raw --sanitize`, GPU
auto-included) and **replayed `--gpu` offline** — the recorded GPU values reproduce
faithfully. The whole amdgpu path (temp/VRAM/power/clock/APU-detect, live + capture
+ replay) is confirmed on real hardware. Bundle: `testdata/captures/
amd-cezanne-gpu-20260618/` (local-only, excluded). KEY: a `nomodeset` boot can't
test GPU; drop it at the GRUB `e`-edit on a live USB.

**Under-load also exercised (same day, `clpeak` OpenCL compute via rusticl).** The
telemetry READS scale correctly under heavy load: util 0→97%, power 3→24W, clock
400→1800 MHz, temp 34→54°C — all parse right, and dsd correctly stayed "healthy"
(heavy but cool/within-limits → no false WARN). The elevated VERDICT thresholds were
NOT reachable on this low-power APU and remain unit-test-only on the verdict side
(reads validated on HW): temp peaked 54°C (< 80°C WARN); this APU exposes **no
`power1_cap`** hwmon node → `TDPLimitW=0` → the TDP-throttle check (correctly gated on
`TDPLimitW > 0`) never fires — no false throttle; VRAM-pressure is APU-suppressed by
design. A *discrete* AMD GPU (or a hotter/power-capped part) is needed to drive the
≥80°C / throttle / VRAM-pressure verdicts on real hardware. Under-load bundle:
`amd-cezanne-gpu-20260618/dsd-gpu-underload.tar.gz` (util 97% / clock 1800, replays faithfully).

---

## G. Debian/Ubuntu OVAL version-awareness — BLOCKED (needs real Ubuntu OVAL fixtures)

The dpkg version comparator (`analysis`/`cvedata` `CompareDpkg`, #231) is built and
verified against the real `dpkg --compare-versions` tool — but deliberately **not
wired** into the Ubuntu/Debian OVAL scan. That scan (`ScanUbuntuOVALPackages`) is
name-based today: it matches an affected package by NAME and ignores the installed
version, so it can over-report a CVE that a newer install already patched.

| Item | Surface | Test target |
|---|---|---|
| Extract per-component fixed version from Ubuntu OVAL | `cvedata/oval_debian.go` `ParseUbuntuOVAL` | real Ubuntu OVAL feed |
| Wire `CompareDpkg(installed, fixedIn)` into the affected/not-affected decision | `ScanUbuntuOVALPackages` | Debian/Ubuntu host |
| Validate no false-negatives introduced (the dangerous direction) | both | real OVAL fixtures |

Why blocked, not just unstarted: name-based over-reporting is a SAFE false-positive;
version-aware matching risks a **false-OK** (silently suppressing a real CVE) if the
fixed-version extraction is wrong. Per the project's deferred-OVAL caution
(agent memory `oval-boolean-tree-deferred`), this needs a real Ubuntu OVAL feed to
validate against before shipping — do not wire it blind. The comparator is proven; the
risk is entirely in the OVAL parsing + the suppress decision.

---

## H. `dsd replay` not fully hermetic — ✅ DONE for default capture path (2026-06-16)

Closed across #339–#349. The double-replay-diff (capture once, replay `--json`
twice, normalise, diff) now shows **zero non-volatile differences** for the default
`dsd health` capture path. Every live input it touches is recorded and replayed:
`os.ReadFile`/`Glob`/`ReadDir`/`Readlink` (#339–#343), `os.Stat` gates via a new
`Source.Stat` (#340–#341), `syscall.Statfs` via `Source.Statfs` (#344), gopsutil via
a generic `Source.Cached` (#345), ping+DNS (#346), service-collector dials +
HTTP/socket APIs incl. docker `apiGet` and cloud IMDS (#347, #349), and disk/multipath
device-list ordering (#348). Mechanism + the "no live I/O outside Source" grep
invariant are in WORKQUEUE.md and the agent's `replay-fidelity-stat-surface` memory.

Deferred (consistent scoping — NOT in the default capture path): NFS reachability
dials and `tls_remote` `--endpoint` dials (opt-in/deep); `ServicesCollector`
(config-gated). The `ServicesCollector` + cloudmeta AWS IMDSv2 token/termination
caching is staged on the in-progress `fix/replay-services` branch (see WORKQUEUE.md).
Left below for history.

## H (history). `dsd replay` not fully hermetic — ✅ DONE (closed by the replay-hermeticity epic, re-verified 2026-07-04)

`dsd replay <bundle>` promises (help text) that "every collector reads from the
bundle instead of the live system" so hardware-specific bugs reproduce on any
machine. Validated 2026-06-16 (CT201, main `01734ff`): replaying the *same* raw
bundle twice produced differing output on live-sampled fields —
`rx_packets`/`tx_packets`, `gateway_ping_ms`/`internet_ping_ms`, memory
free/used, context-switch rate. So several collectors ignore the bundle and
re-measure the live host during replay.

This is the false-green class: an AMD-thermal / EDAC / NVMe bug captured on the
affected box will **not** reproduce faithfully on replay if the relevant
collector live-samples instead of reading the bundle — replay would render the
replaying host's clean state and look like the bug vanished. The stated use case
("diagnose on any machine") is silently undercut.

**Re-verified 2026-07-04 on a real Linux guest (pve01 CT202, Ubuntu 24.04 LXC):**
captured a raw bundle, then replayed it twice with real live perturbation injected
between the two replays — 30 real pings to 8.8.8.8 (to move `rx_packets` if the
network collector were live-sampling) and a 50 MB memory-touching allocation (to
move `free_gb`/`used_pct` if the memory collector were live-sampling). Both
replays came back byte-identical on `Network` (`rx_packets: 423165` both times,
`gateway_ping_ms`/`internet_ping_ms` unchanged) and `Memory`
(`free_gb`/`used_pct` unchanged), and a full sorted-JSON diff of the two replays
(timestamp + per-check `duration` stripped) was empty end-to-end — no field
anywhere drifted. The v1.0.2 replay-hermeticity epic (#339–#349, #351) plus the
later platform-context follow-ups (#586 clock, #595 opt-in probes, #599
container-context, #601 cloud-env+profile) closed this gap; the entry was just
never flipped to done. No further fix needed here.

| Item | Surface | Test target |
|---|---|---|
| Audit which collectors honour the bundle vs hit live system in replay path | `internal/source` (Live vs bundle Recorder wiring), replay cmd | ✅ audited — CT202 double-replay under injected live traffic/memory pressure, byte-identical |
| Net/mem/ping/ctxsw collectors must read bundle inputs under replay, or be explicitly marked replay-excluded (not silently live) | offending collectors | ✅ confirmed — no live leak on Network/Memory under real perturbation; full-JSON diff empty |

Repro: `dsd capture --raw`, then `dsd replay --json B.tar.gz` twice, diff.
Differences on non-timestamp fields = live leak. Not GATED — replay fidelity is
the feature's whole premise.

**Sibling found + fixed while auditing the "unstarted" tail of the parked
replay-hardening backlog (agent memory `replay-hardening-backlog-parked`,
2026-07-04):** the exported `PlatformServiceCmd`/`PlatformServiceCmdSudo`
(`internal/analysis/heuristics.go`) built their remedy string from the raw
`runtime.GOOS`/`hostInitSystem()` instead of the replay-pinned
`effectiveGOOS()`/`effectiveInitSystem()` that `platform.SetReplayPlatform`
sets up (see `cmd/replay.go`). These two functions are reached from
`internal/analysis/correlate.go`'s `CorrelateDeep` — the low-entropy/haveged
remedy line — which `cmd/health.go:223` calls on **every** `dsd health --deep`
and `dsd replay --deep` run. So a low-entropy bundle captured on an
OpenRC/Alpine host and replayed on a systemd box would render `to fix:
systemctl enable --now rngd` (the replaying host's form) instead of the
captured host's `rc-update add rngd && rc-service rngd start` — the exact
"remedy hint reflects the wrong host" bug class `effectiveDistroID` already
guards for `dnf`/`apt`, just missing on this one call path. Fixed by routing
both functions through `effectiveGOOS()`/`effectiveInitSystem()`; zero
behavior change for their other (all live-only, non-replay) callers —
`dsd proc`/`docker`/`cron`/`kvm` — since the replay pin is unset there.
Regression guard: `TestPlatformServiceCmdReplayAware`
(`heuristics_hints_test.go`), proven to fail before the fix and pass after.

**Second sibling found + fixed (2026-07-04):** no env-var read was routed
through `internal/source` at all — `Source` had no such primitive, so every
`os.Getenv` in a collector was inherently live-only. Added `getenv(name)`
(`internal/collectors/fsaccess.go`), a `lookPath`-shaped wrapper over the
existing generic `activeSource.Cached` primitive (no new `Source` interface
method needed). Routed the one confirmed verdict-relevant site:
`detectSessionMode` (`steamos_linux.go`) reads `XDG_SESSION_DESKTOP` to decide
`models.SteamOSInfo.SessionMode` (Game Mode vs Desktop Mode) — a rendered
field, reached by `dsd steamos`/`dsd health` and their replay counterparts. A
Steam Deck bundle captured in Game Mode would replay as "desktop"/"unknown"
from any shell that isn't itself a gamescope session (i.e. every normal
replay). Live-verified end-to-end on the SteamOS-spoofed rig (pve01 VM 102,
192.168.10.60): captured with `XDG_SESSION_DESKTOP=gamescope` set, replayed
with it unset — `SessionMode` still read `"gamemode"`. Regression guards:
`TestGetenvRoutesThroughSource` (`fsaccess_test.go`) and
`TestDetectSessionModeReplaysCapturedEnv` (new `steamos_linux_test.go`), both
proven to fail before the fix and pass after.

Two other raw env-var reads were found and deliberately NOT routed (lower
severity, considered out of scope for this pass): `steamUserHome()`'s `$HOME`
fallback and `kubeadmKubeconfigFlagFor`'s `KUBECONFIG` check are path/flag
*selection* decisions — if capture and replay environments disagree, the
replay-time behavior fails safely (a `Replay.Run`/`Stat` lookup miss returns
the loud `ErrNotRecorded`, or a benign zero/absent value), not a silently
wrong-but-plausible verdict like the two fixed bugs above. `gpu_linux.go`'s
`DISPLAY`/`WAYLAND_DISPLAY` gate feeds only the cosmetic `MesaVersion` display
string (no threshold reads it). `dns_resolver_linux.go`'s `SUDO_USER` check is
inside `dsd net deep`'s resolver audit, which isn't wired into `dsd
health`/`dsd replay` at all yet (already-documented "opt-in/deep probes not
yet routed" gap, CLAUDE.md).

---

## I. `checks[]` array has no stable ordering — ✅ DONE (render-boundary sort + §I-class map-iteration sweep, fix/k8s-cert-0day)

Two `dsd health --json` runs on the same host emit `checks[]` in different array
positions (same 23-check set, same content, shuffled order). Confirmed
2026-06-16 across same-locale runs — collector scheduling non-determinism, not a
data difference. Benign for consumers that index by `name` (jq); a sharp edge
for byte/line-level golden-file tests on `--json` (they flake) and `diff`-based
support workflows (noisy).

**Done (#348):** the map-iteration ordering *within* a check's `raw` — disk
`Drives[].Mounts` (`range mountsByDev`) and the multipath device list (`range
deviceMap`) — now sorted, so those sub-lists are byte-stable.

**Done (top-level + insights):** `render/json.go` stable-sorts the top-level
`checks[]` by name and `insights[]` worst-first-then-name at the render boundary
(`BuildJSONOutput`). This was already in-product when re-audited — the "still
GATED" note below was stale.

**Done (`apparmor_groups[]`):** `collectAppArmorDenials` sorts count-desc then
profile/path/op (security_linux.go) — the 2026-06-18 re-observation is closed.

**Done (§I-class map-iteration sweep, 2026-06-21):** a full sweep for *any*
map→slice / map-pick feeding rendered or JSON output found and fixed three more
tie-break/order nondeterminisms with unit-test guards:
- `detectSSIDConflict` (steamos) returned the first conflicting SSID in map order
  → now lexicographically smallest.
- `ruleServiceMemoryLeak` (correlate) picked the most-OOM-killed `leaker` with no
  tie-break → now smallest name on a tie.
- `activeInsights` (render/story) built its slice from a map → now name-sorted, so
  narrated story line order is stable.
Already-sorted (verified clean): auth `TopSources`, logs `topMessages`,
multipath devices, security AppArmor groups, json `checks[]`/`insights[]`. The
prefix-match loop in `BuildJSONOutput` (`range insightMap`) is order-independent
(takes the worst severity).

---

## Locale safety — ✅ VALIDATED (2026-06-16), no open work

Forced-C subprocess discipline (`localeSafeCmd`/`localeSafeEnv`/`localeSafeExec`,
`LC_ALL=C`/`LANG=C`) confirmed holding on current main. Ran `dsd health --json`
under `en_US.UTF-8` vs `es_ES.UTF-8` on CT201 (locale proven hostile — `printf`
reads dot-decimals as `número inválido`). After controlling for check-ordering
(§I) and live-counter drift, every parsed value is a clean dot-decimal under
es_ES — no comma corruption, no zeroing, no garble; same exit code, same
23-check set, same severities both locales.

Root cause of the no-leak result (code audit, not just the live run): all ~260
numeric parses use Go's `strconv`, locale-independent by language design (always
reads `.` as decimal sep). The forced-C wrapper is real defense-in-depth — it
covers *string* uniformity (column headers, status words, month names; the #82
dmesg `[lun jun 8]` bug) that strconv-immunity does not. Committed guard:
`internal/collectors/exec_locale_test.go` — `TestCollectorsUseLocaleSafeExec`
(static: no raw `exec.Command` outside wrappers) + `TestParsingIsLocaleStable`
(behavioral: strconv parses dot-decimals, rejects comma-decimals under forced
es_ES env). Both run in default `go test`, no host.

A live double-run integration test was prototyped and discarded as inherently
flaky: with no locale-sensitive parser to leak into, comparing `--json` across
two shell locales only surfaces live-counter jitter (run-queue, CPU MHz, packet
counts) — an unbounded denylist. The unit guards test the actual risk.

UI/output **translation** stays demand-gated (no user has asked; sysadmin/SRE
buyer operates tooling in English; localized ops output hurts log/screenshot
searchability). Discipline regardless: `--json` is born locale-invariant
(English keys, raw numbers, ISO 8601); any future translation lives only in the
`render/` human layer, never the data plane.

---

## J. SMART wear% — guard the sibling 231/233 branch (hardening) — ✅ DONE

The garbage-wear bug from the 2026-05-15 MacBook story (`3491877946276% used`)
came from **attribute 173's raw value** reaching `WearPct`, and was already
**fixed** the same evening in `05b8124` ("SMART attr 177/173 wear% uses
normalised value not raw") — ~2h after the marketing capture was taken. Verified
on the T1 Apple SSD (row 19) 2026-06-16: current `dsd hardware` correctly shows
`23% used` (the 173/177 guard rejects 173's out-of-range raw `3491877946276` and
lets attribute 177's normalised 077 → 100-77=23%). The marketing doc just froze
pre-fix output; nothing live to fix on this hardware.

Remaining (defensive, lower priority): the **sibling 231/233 branch** (SSD Life
Left / Media Wearout) lacked the same `attr.Value > 0 && attr.Value <= 100` guard
the 173/177 branch has — a copy-paste sibling-divergence (§E.3). Other SSDs report
wear via 231/233 and bad firmware there would produce the same garbage. Guard
added in this change for parity; **no live repro** (the Apple SSD has no 231/233
attribute, so this is hardening, not a confirmed-bug fix).

| Item | Surface | Status |
|---|---|---|
| Guard 231/233 branch to match 173/177 | `hardware_linux.go` ~L184 | ✅ done this change (hardening; unverified on real 231/233 firmware) |
| 173 garbage on Apple SSD | `hardware_linux.go` | ✅ already fixed `05b8124`; verified clean on row 19 |

---

## K. Disk false-CRIT on read-only image filesystems — ✅ DONE (#382, 2026-06-17)

Surfaced by the first real AMD-silicon node (Ubuntu 26.04 live USB, PLATFORM_COVERAGE
row 21). `dsd health` reported `Disk CRIT — disk usage at 100% on /cdrom (/dev/sda1)`
on a healthy live boot. Root cause: inherently read-only image filesystems
(iso9660, squashfs, erofs, cramfs) are packed to capacity at build time — 100%
used is their normal state and no admin action can free space, so the usage/inode
level scoring was firing a guaranteed false CRIT on every live-USB `/cdrom`,
snap-backed squashfs, and AppImage mount.

Fix: added `isInherentlyReadOnlyFS()` and skip usage/inode scoring for those
fstypes (`checkDisk`, heuristics.go). The mount is still reported transparently in
the inline summary (`13 mounts, max 100% (/cdrom)`) — data shown, verdict corrected.
Writable filesystems unaffected: full ext4 still CRITs; the read-only error-remount
WARN (writable fs dropped to ro after I/O errors) still fires via its own allowlist.

Verified end-to-end on the AMD node: live run + replay of captured bundle both show
`Disk OK`. Regression guards in `TestCheckDisk`: full image fs clean; full writable
ext4 still CRIT; full read-only ext4 still WARN; image-fs inode-full clean.

| Item | Surface | Status |
|---|---|---|
| Skip usage/inode scoring for iso9660/squashfs/erofs/cramfs | `heuristics.go` checkDisk + `isInherentlyReadOnlyFS` | ✅ done #382 |
| Regression guards (image clean / writable still CRIT / ro-remount still WARN) | `heuristics_round10_test.go` TestCheckDisk | ✅ done #382 |

---

## L. NVMe SMART implausible-value → false end-of-life CRIT (VMware virtual NVMe) — ✅ DONE (fix/nvme-smart-plausibility-L, 2026-06-18)

> **Sibling found + fixed live 2026-06-26 (PR #538):** the `health`/Drives gate held
> on the real 11759°C / spare-1% vNVMe, but the standalone **`dsd hardware`** thermal
> renderer had NO plausibility gate → false `Temperature: CRIT 11759°C`. cmd↔health
> divergence, invisible non-root (SMART read fails), only root+smartctl exposed it —
> run-as-both caught it. Fixed via `driveThermalLevel()` + `TempPlausible`/`TempCeilNVMe`,
> validated on the live drive. See memory `vmware-vcd-tenant-guest`.

Fixed by a plausibility gate in `checkNVMe` (`nvmeSmartPlausible`): a device whose
SMART log was read (`SmartRead:true`) but is physically impossible (temp ∉
[-40,125]°C, spare/threshold ∉ [0,100], counters > sane ceiling) is routed to a
new "implausible SMART data — health unverified, values rejected" **WARN** and its
fields are NOT scored — closing the false "near end of life" CRIT. Validated live
on the originating device (VMware vNVMe, guest 192.168.30.10): the Drives check
now emits the WARN and the NVMe CRIT is gone (the remaining CRIT that run was an
unrelated DBus false-positive → §M, separate branch). Regression cases in
`TestCheckNVMe`: vmware-garbage→WARN-not-CRIT, each implausibility trigger alone,
and boundary guards proving a real failing drive still CRITs / real high temp
still WARNs. Original investigation below for history.

First VMware Cloud Director node (vcd-msk-3, Ubuntu 22.04 guest 192.168.30.10,
2026-06-18 — see PLATFORM_COVERAGE). A 1 GB VMware Virtual NVMe disk hot-added
alongside PVSCSI/LSI-SAS/LSI-Parallel/SATA/IDE test disks exposes a SMART health
log full of nonsense, and `dsd health` ingests it and raises a **false CRIT**.

Raw `sudo nvme smart-log /dev/nvme0` on the device returns:
`temperature 11759°C`, `available_spare 1%` vs `available_spare_threshold 100%`,
`Data Units Read 56.67 YB`, `power_on_hours 1.1e21`, `power_cycles 1.8e20` —
i.e. out-of-range temps and counters sitting at ~2^63–2^64 (uninitialised /
sentinel fields in VMware's virtual NVMe). The read **succeeds**, so this is
parseable-but-garbage, not unread.

dsd's behaviour (confirmed by a root/non-root run pair, 2026-06-18):
- **root:** read succeeds → `smart_read:true`, `temp_c:11758.85`,
  `available_spare_pct:1`, `spare_threshold_pct:100`, `Drives` check →
  **CRIT** `"/dev/nvme0 spare capacity at 1% (threshold: 100%) — drive near end
  of life"` + WARN on temp. Overall **verdict flips WARN → CRIT**.
- **non-root:** read fails → `smart_read:false` + all-zero struct. No CRIT, but
  the zeros are indistinguishable from a measured 0 (§E.4) — only the missing
  privilege accidentally avoids the false CRIT.

So there is **no plausibility/reject-before-score guard**: the spare<threshold
end-of-life test fires on data whose own sibling field (11758°C) is physically
impossible. A real customer running `dsd` as root on any VMware NVMe guest from
these templates gets a spurious "drive dying" CRIT — a false positive in the
shipped health verdict.

Fix: add a bounds-check layer on the NVMe SMART struct *before* scoring —
temp ∈ [-40, 125]°C, spare/used/threshold percentages ≤ 100, counters below a
sane ceiling. On any implausible field, treat the whole SMART read as "couldn't
measure" (the honest-degradation pattern KernelSec/Hardening already use:
`-1`/`unknown`/explicit reason), **not** as measured values, and **do not** let
the end-of-life or temp tests fire. Distinct from §J (which guards garbage *wear%*
from bad SATA attr raw values): same class — raw-tool parser trusts a real
device's lying output — different tool (`nvme smart-log` vs `smartctl` attrs).
Strongest argument yet for a sanity layer on raw-tool parsers; the `/proc`
numeric fuzz harnesses should gain an `nvme smart-log` sibling.

| Item | Surface | Status |
|---|---|---|
| Plausibility-gate NVMe SMART before scoring (temp/pct/counter bounds) | nvme collector + `Drives` heuristic | READY — false CRIT confirmed root, repro on VMware vNVMe |
| Implausible read → "couldn't measure", not zeros and not CRIT | nvme render + scoring | READY (§E.4 surfacing + §J reject-before-score) |
| Fuzz harness for `nvme smart-log` parser (sibling to /proc parsers) | fuzz/ | demand/defensive |
| Empty/unpartitioned disks (sda–sde, 1 GB, no FS) — no false WARN/CRIT | disk enum | ✅ verified clean this run (no per-disk status fired) |

Also observed same run (logged, not new bugs): **PVSCSI driver detection correct**
despite blank `lsblk` TRAN on the paravirtual disk (`pvscsi_loaded:true` reads
`/proc/modules`, not transport); **device-name instability** — adding controllers
moved the root disk `sda`→`sdc` (Ubuntu boots by UUID; caution for any name-keyed
logic); **`fd0` phantom-floppy I/O errors** correctly deduped in Logs (`×2`),
benign VMware-template artifact (§E.4 virtualization-noise candidate, park).

---

## Systemd failed-unit listing — guarantee timeout never reads as "none" — ✅ DONE (2026-07-04)

Same 2026-06-18 root run: `systemctl list-units` did not complete under load, and
dsd correctly emitted `failed_units_unknown:true` + INFO `"could not list failed
units … failed-unit status is unverified"` — the honest path. But an earlier clean
run showed `failed_units:null` (confident "none failed"). Risk: the timeout/error
path must **always** yield `failed_units_unknown`, never collapse to an empty-but-
confident `null` that renders as "no failures."

Added the regression test this item asked for:
`TestSystemdCollect_FailedUnitsTimeoutNeverReadsAsNone` (`systemd_test.go`) drives
`SystemdCollector.Collect` through a fake `source.Source` that fails every `Run`
call (simulating the list-units timeout) and asserts `FailedUnitsUnknown=true` +
an empty (not fabricated) `FailedUnits`. Confirmed the test fails when the
coupling (`FailedUnitsUnknown: failedErr != nil` in `systemd.go`) is broken, so it
actually guards the invariant rather than trivially passing. The coupling itself
needed no code change — it was already correct, just untested at the collector
level (only the downstream heuristic had a regression test).

---

## M. D-Bus false-CRIT — "unknown" state treated as "failed" — ✅ DONE (fix/dbus-unknown-not-failed-M, 2026-06-18)

Found on the VMware Cloud Director guest (Ubuntu 22.04, 192.168.30.10) during the
2026-06-18 session: `dsd health` reported **CRIT "D-Bus system message bus has
failed"** on a host where `systemctl is-active dbus` returns `active` and
`busctl` lists live connections — a false CRIT, and a scary top-line one.

Two compounding silent-failure flaws (the false-OK class, inverted — a failed
*measurement* rendered as a failed *subject*):
1. **Wrong unit name.** The collector ran `systemctl is-active dbus.service`.
   On modern Debian/Ubuntu (and these VMware templates) the bus resolves via
   `dbus` (alias → `dbus.socket`/`dbus-broker`), and `is-active dbus.service`
   returns empty+nonzero → status `"unknown"`. `is-active dbus` returns `active`.
2. **"unknown" collapsed to "failed".** `info.Active = status=="active"` made
   unknown→`active:false`, and `checkDBus` CRIT'd on anything not active/n-a — so
   "couldn't determine" produced the same CRIT as a genuine "failed".
3. **Bonus:** `collectDBusLastError` returned the last *non-empty* journal line
   regardless of severity, so it captured `"Successfully activated service
   org.freedesktop.timedate1"` and reported a success message as `last_error`.

Fix (collector + heuristic, no `--json` schema change):
- Query `dbus`, not `dbus.service` (resolves the alias; the working invocation).
- Empty result → explicit `"unknown"`; heuristic treats anything other than
  `failed`/`inactive` as **INFO** "state could not be determined — health
  unverified, not assumed failed", never CRIT. Only explicit failed/inactive CRITs.
- `collectDBusLastError` now uses `journalctl -p err` (error priority only) and is
  called only when status is confirmed failed/inactive — no success-line-as-error.

Validated live on the originating guest: DBus check now `OK`
(`status:"active", active:true`), zero DBus insights, false CRIT gone. (The run's
remaining CRIT was the unrelated NVMe §L, fixed on its own branch.) Regression in
`TestCheckDBus`: unknown→INFO, activating→INFO, failed→CRIT, inactive→CRIT,
active→clean.

| Item | Surface | Status |
|---|---|---|
| Query `dbus` not `dbus.service`; unknown≠failed | `dbus_linux.go` Collect | ✅ done |
| Heuristic: non-failed/inactive status → INFO not CRIT | `heuristics.go` checkDBus | ✅ done |
| `last_error` severity-filtered (`-p err`), only when down | `dbus_linux.go` collectDBusLastError | ✅ done |
| Regression: unknown/activating→INFO, failed/inactive→CRIT | `heuristics_round6_test.go` TestCheckDBus | ✅ done |

---

## N. VMware live-guest probe checklist — PARTIALLY CLOSED (live session 2026-06-26; active-limit items remain tenant-blocked)

> **2026-06-26 live session** (real VCD guest `ubuntumin`, ssh andrei@5.35.120.132:2222;
> memory `vmware-vcd-tenant-guest`):
> - ✅ **§N.1/§N.2 settled** — collector bails to `stat_available:false` on probe failure,
>   heuristic gates on it (logic-proven + already unit-tested); confirmed live the read
>   works non-root. No zero-vs-unread false-negative.
> - ✅ **At-rest detection confirmed on real hardware** — cpu/mem limit, balloon
>   cross-checked byte-exact vs `vmware-toolbox-cmd stat`; emulated NICs; SCSI timeouts.
> - ✅ **§L sibling found+fixed** (PR #538, `dsd hardware` thermal false-CRIT — see §L).
> - 🆕 **NEW bug found+fixed (PR #539):** dsd false-WARNed on a NON-BINDING limit —
>   cpu_limit auto-scaled to == capacity (2 vCPU × 2993 MHz; steal stayed 0 under load),
>   mem_limit 2048 ≥ RAM 1919. Now INFO "non-binding" when provably ≥ capacity; WARN
>   otherwise. §O "right reading, wrong context" class.
> - 🔴 **§N.3 / §N.4 ACTIVE remain BLOCKED — tenant constraint, now DEFINITIVE:** the VCD
>   "Edit Compute" role exposes NO Reservation/Limit/Shares fields, and limits **auto-scale
>   with capacity** (added a 2nd vCPU → cpu_limit auto-went 3000→6000, stayed non-binding).
>   So steal/balloon cannot be induced here. §N.4 feature is unit-proven (#536) + at-rest
>   live-confirmed; active validation needs **admin vSphere or our own lab**, NOT this tenant.
>   Don't re-attempt the add-vCPU workaround — proven dead end.
> - 🟡 **Hot-add diagnosis** explored + SHELVED — guest-side detection ambiguous on small
>   VMs (single NUMA node expected regardless); low-confidence, not worth building.
> - ⬜ **§N.5 (PVSCSI readable-SMART)** not done this session (smartmontools now installed;
>   NVMe path validated, the SATA/PVSCSI sd*-drive SMART parse still to confirm).

Items identified during the 2026-06-18 VCD session that need a *live VMware guest*
to validate and weren't closable then — either gated by tenant role (couldn't edit
reservation/limit fields) or simply not exercised before access lapsed. Grouped
here by shared blocker: one VMware guest (own vSphere, a pilot's env, or a
re-provisioned tenant **with admin rights**) closes the whole class in one session.
Most have a plausible bug at the end — they're §E.4 / silent-failure probes, not
just coverage.

1. **open-vm-tools removed → do host-limit fields read "unknown" or a misleading 0?**
   (the sharpest one.) `mem_limit_mb`/`cpu_limit_mhz`/`balloon_mb` are read through
   the tools stat channel. Remove open-vm-tools (`apt remove open-vm-tools`) and
   re-run: the limit fields should go **absent/unknown**, NOT `0`. If they read `0`
   and the VMware heuristic interprets that as "no limit set" rather than "couldn't
   read", that's a §E.4 zero-vs-unreported false-negative — dsd would silently stop
   reporting a real host limit the moment tools are absent. Reversible: reinstall.
2. **Tools stopped/absent — collector-side detection on real hardware.** The
   *heuristic* paths are unit-tested (`vmware_test.go`: ToolsInstalled:false → WARN,
   ToolsRunning:false → WARN). Not exercised live: the *collector* readers
   `vmwareToolsRunning()` (/proc comm scan) and `vmwareToolsInstalled()` (binary
   probe) against a genuinely stopped/removed install. `systemctl stop vmtoolsd`,
   re-run, confirm `tools_running:false` actually surfaces. (Low — readers are
   simple; a fake-/proc collector test would also cover it.)
3. **Active ballooning (`balloon_mb > 0`).** GATED 2026-06-18 — couldn't lower the
   memory limit below allocated RAM from `user_adm`. With limit-edit rights: set
   mem limit < allocated, drive in-guest memory demand, confirm `balloon_mb` goes
   non-zero AND dsd attributes it to **host reclamation** (a host condition) vs
   in-guest memory pressure. Conflating the two would be a real diagnostic bug.
4. **Active CPU-limit throttle (`steal_pct > 0`).** GATED 2026-06-18 — the 3000 MHz
   limit on a 1-vCPU guest is ~1 full core, never throttled under `stress-ng --cpu 1`
   (steal stayed 0, dsd correctly OK — no false alarm). With limit-edit rights: set
   cpu limit < 1 core, load the guest, confirm steal goes non-zero AND dsd connects
   high steal to the known `cpu_limit_mhz` as "host-throttled" rather than reporting
   bare high CPU and missing the *why*.
5. **PVSCSI-attached SMART parse path.** §L validated that *implausible* NVMe SMART
   is rejected; separately, the PVSCSI controller branch (`pvscsi_loaded` detection
   confirmed working) has not had a drive with a *readable, plausible* SMART log
   attached through it. Attach a disk on the Paravirtual controller with real SMART
   and confirm the parse path is clean (not just the rejection path).
6. **vMotion / snapshot artifacts.** If a pilot env exposes live migration: post-
   vMotion clock skew and guest stun-time. dsd's Clock check would be the surface;
   untested against a real migration event. Demand/opportunity-gated.

Provenance: full capture set in
`dashdiag-private/marketing/marketing-assets/vmware-vcd-20260618-data/`. The
detection-at-rest half of items 1/3/4 is confirmed working; the active/absent half
is what's unverified.

---

## O. "Correct reading, wrong context" false-CRITs on Proxmox hosts — ✅ DONE (4 fixed, fix/proxmox-context-falsecrits-O; O.4 BUG-099, 2026-07-10)

A coherent new bug *class*, distinct from §L/§M. There the bug was a failed or
garbage *measurement* rendered as a failed subject. Here the measurement is
**correct** — the bug is **misattributing its meaning** because the collector
doesn't understand the Proxmox/virtualization context it's running in. All three
below were found on a real AMD EPYC Proxmox host (`khhv01`, 252 GB RAM, 4 NUMA
nodes, Debian 12 / kernel 6.8-pve, dsd v1.4.0) via a capture a user sent
2026-06-19, and **confirmed false by the host's owner**. Full repro bundle +
replay output in
`dashdiag-private/marketing/marketing-assets/amd-gpu-friend-20260619-data/`
(`dsd.tar.gz` — replayable offline, no live host needed to validate fixes).

The host's verdict was **CRIT** driven entirely by these three. All three are
false. Owner's words (paraphrased, RU): the LVM is the default Proxmox-created
LVM on NVMe and is nearly empty; the ZFS is real but **passed through to a VM**,
not the host's; the journal-corruption CRIT is "just nonsense".

### O.1 — LVM: scores VG allocation, not thin-pool usage (Proxmox default layout)
- **Fired:** `CRIT volume group pve is 98% full (16.0 GB free of 930.5 GB)`.
- **Reality:** on a Proxmox host the `pve` VG is the default thin-pool layout —
  Proxmox *allocates* almost the whole VG to a thin pool (`data`) by design, so
  "VG ~98% allocated" is the normal healthy state. The capture's own `lvs`
  output shows the `data` thin pool at **8.37% data / 0.51% metadata** — i.e.
  ~92% free. dsd read VG allocated-vs-free and CRIT'd; the number that matters
  (`data_percent`) was already collected and ignored.
- **Fix:** when the host is Proxmox (detectable — `pveversion` is collected) and
  the VG backs a thin pool, score the **thin pool's `data_percent` / metadata%**,
  not VG allocation. A nearly-empty thin pool in a fully-allocated VG is healthy.
  Thin-pool *data* or *metadata* approaching 100% is the real CRIT condition.
  (Generalises beyond Proxmox: any thin-provisioned VG should be scored on pool
  usage, not VG free.)

### O.2 — ZFS: CRITs on `zfs-import-scan.service` failure with no host pools
- **Fired:** `CRIT unit zfs-import-scan.service has failed`.
- **Reality:** the host has no ZFS pools to import — the ZFS hardware is **passed
  through to a VM**. `zfs-import-scan` failing (or `zfs-import-cache` when pools
  are cache-imported) is expected/benign when the host itself manages no pools.
  dsd saw the failed unit and didn't understand the pools aren't the host's.
- **Fix:** don't let a failed `zfs-import-*.service` drive a CRIT unless there are
  actually imported/expected ZFS pools **on the host** (`zpool list` non-empty).
  No host pools + failed import unit → INFO/skip, not CRIT. Same "service failed
  but failure is expected in this configuration" pattern as a Systemd suppression.

### O.3 — Logs: journal-corruption CRIT doesn't distinguish active vs archived (`.journal~`)
- **Fired:** `CRIT journald journal corruption detected — some logs may be
  unreadable or missing`.
- **Reality:** of 4 `journalctl --verify` runs in the capture, **3 PASS, 1 FAIL**
  — and the FAIL is on a rotated `*.journal~` archive (bad hash at one offset,
  87% into an 8 MB deactivated segment). All **active** journals pass. A `~` file
  is a journal systemd couldn't cleanly deactivate, common after an unclean
  shutdown; one bad block in a historical archive does not mean current logging
  is compromised. A blanket "any verify FAIL → CRIT, logs may be missing" fires
  on a large fraction of real hosts and is the trust-eroding false-CRIT Principle
  4b warns against.
- **Fix:** distinguish **active**-journal corruption (real CRIT — current logging
  compromised) from **archived `.journal~`** corruption (WARN/INFO — historical
  artifact). Gate the severity on whether the failing file is an active journal
  or a rotated `~` segment.

**The class lesson (worth its own note):** dsd reads the raw signal correctly but
misattributes meaning because it lacks the host/virtualization context — Proxmox
thin-pool intent, ZFS passthrough, active-vs-archived journals. This is the
mirror of §L/§M (there: bad measurement → bad verdict; here: good measurement →
bad interpretation). Watch for siblings wherever a check scores a raw number
without asking "what does this number mean *on this kind of host*." Real-operator
feedback was essential — the thin-pool intent and the ZFS passthrough are not
derivable from the data alone; only the owner knew. (Validates Principle 4a: real
hardware + real operator surfaces what synthetic fixtures cannot.)

| Item | Surface | Status |
|---|---|---|
| O.1 LVM thin-pool usage vs VG allocation on Proxmox | LVM collector + heuristic | ✅ DONE (fix/proxmox-context-falsecrits-O) — VG-fullness skipped for thin-pool-backed VGs (`analysis.VGBacksThinPool`, single source of truth shared with `dsd disk`); thin-pool data/meta% still scored. **Validated end-to-end on the EPYC bundle: base v1.5.1 CRIT'd "pve 98% full", fixed binary → LVM ✅.** |
| O.2 ZFS import-service CRIT only if host pools exist | ZFS/Systemd heuristic | ✅ DONE — `zfs-import-{scan,cache,@}` failure → INFO when no host ZFS pools imported; `SystemdInfo.ZFSPoolsPresent` set by ApplyThresholds pre-scan from the ZFS/Disk collectors. Unit-tested (heuristic + e2e pre-scan). |
| O.3 Logs active vs archived `.journal~` corruption severity | Logs collector + heuristic | ✅ DONE — the collector already verifies *only* archived (`*.journal~`) segments (active ones race with writers, systemd#35916), so a hit is always a historical artifact → downgraded CRIT→WARN with honest wording. Unit-tested. |
| Replay-based regression for all three (offline, from bundle) | replay test | PARTIAL — O.1 validated end-to-end against the EPYC bundle. O.2/O.3 can't be re-validated by replay of this bundle: it was captured on v1.4.0, and the v1.4.0→v1.5.1 collector-code skew means the journal-verify + failed-unit signals are no longer reconstructed in a v1.5.1 replay (base v1.5.1 replay already shows them clean). Covered by unit tests instead; would re-fire on a *live* v1.5.1 run. |

**O.4 — ✅ DONE (2026-07-10, BUG-099)** — turned out not to need the owner after all: replaying
the EPYC bundle with base v1.5.1 surfaced **2 `PVE storage … INACTIVE` CRITs** (`VM03CR (dir)`,
`Storage (dir)`) absent from the v1.4.0 capture, same "correct-reading/wrong-context" class as
O.1–O.3. Reproduced live on pve01 instead of waiting on the owner: `pvesh get
/nodes/localhost/storage` already returns an `enabled` field alongside `active` in the same
response dsd was already fetching — an admin-disabled or optional/removable mount reads
`active:0, enabled:0`, a genuinely broken one reads `active:0, enabled:1`. dsd was discarding
`enabled` and CRITing on any `!active`. Fix: thread `enabled` through the model/collector,
CRIT only when `enabled && !active`, INFO "disabled — skipping" otherwise. Verified live with
two throwaway pve01 test storages (one `--disable 1`, one `--is_mountpoint yes` unmounted):
disabled case dropped CRIT→INFO, genuinely-broken case still correctly CRIT'd.

Also confirmed clean this capture (good behaviour, not bugs): **no false GPU** —
the host's `card0` has `device/vendor: not_exist` (virtual console DRM, no
discrete GPU bound; the real AMD GPU is passed through to a VM), and dsd correctly
emitted **no GPU check at all** rather than misreporting the console device.
Consequently this capture does **NOT** close §F (no host-bound discrete amdgpu) —
§F still needs a capture from inside the GPU-passthrough VM, or the GPU bound on
the host. AMD-CPU thermal path validated incidentally: k10temp Tctl + Tccd1–3 on
a 4-NUMA EPYC, CPU Thermal correctly 57°C.

---

## P. K8s-on-VMware vertical — ✅ VALIDATED LIVE + 1 fix (fix/k8s-event-recency, 2026-06-19)

The prospective client's exact topology is **k3s/Tanzu on VMware** (Docker + managed
k8s on a VMware estate, OpenStack being built in parallel; founder's priority:
*kubernetes-on-vmware > openstack*). Rather than predict, we stood up k3s on the real
VMware tenant guest (vcd-msk-3, 192.168.30.10 behind 5.35.120.132:2222) and ran the
full `dsd health` vertical on the genuine topology.

**Result — the vertical coheres end-to-end on real hardware:** VMware layer (emulated
e1000/e1000e NICs, SCSI 30s<180s timeout, host CPU 3000MHz + mem 2048MB limits), K8s
deep OS-layer (the #271 k3s-aware paths all correct: flannel detected, CNI bins found
under `/var/lib/rancher`, embedded kubelet + bundled containerd recognised), and the
container layer via k3s's containerd. node=1/pods=7/0-not-ready. dsd produced useful
k8s-specific advice (`fs.inotify.max_user_watches` low, `vm.swappiness=60` high for a
k8s node). Note: the K8s OS-layer is **deep-only** (`dsd k8s --deep` / `health deep`).

| Item | Surface | Status |
|---|---|---|
| K8s Warning-event recency gate — stale startup events false-WARN a healthy cluster | `heuristics_virt.go` events check | ✅ DONE #421 — gate on last-seen `Age` (recent≤5m→WARN, quiesced→INFO); verified live |
| Determinism: event reason-summary built from Go-map iteration | `heuristics_virt.go` | ✅ DONE #421 — sorted count-desc/name-asc (replay/JSON-stability) |
| Tanzu (TKG) OS-layer — kubeadm/Photon/**Antrea** | `collectK8sOSLayer` (k8s.go) | PARTIAL — code review says largely TKG-ready (kubelet/containerd/CNI-bins/cert paths cover kubeadm; Antrea won't false-CRIT). Needs real TKG to validate |
| No *positive* CNI-health check for non-flannel CNIs (Antrea/Calico/Cilium) | k8s OS-layer | BLOCKED (needs TKG) — mild false-OK; pod-not-ready/sandbox events catch a broken CNI |
| `checkCertExpiry` 0-day sentinel collision (cert expiring today reads as "unset") | k8s.go ~578 | ✅ DONE (fix/k8s-cert-0day) — `CertExpirySoon` companion bool gates the WARN so 0 days (within 24h) no longer collides with the zero-value "none"; regression test in heuristics_deep_test.go |

Rig kept running on the tenant guest for re-validating K8s changes on the true
topology. The k3s-on-VMware path is now a concrete demo/pilot asset.

---

## Q. SATA/SAS SMART implausible-value → false drive-failure CRIT — ✅ DONE (fix/sata-smart-plausibility-J2, 2026-06-22)

The §L §E.3 sibling, found by code inspection while triaging post-VMware-block
work. §L added `nvmeSmartPlausible` so garbage-but-parseable **NVMe** SMART
(VMware vNVMe: 11758°C, spare 1% vs threshold 100%, counters ~2^63) is rejected
before scoring. The **SATA/SAS** path (`checkNVMe`'s second loop in
`heuristics_storage.go`) had no equivalent gate — it scored `TempC`,
`ReallocatedSectors`, `PendingSectors`, `UncorrectableErrors` straight from the
parsed values. Those error counters come from **raw ATA SMART attribute** fields
(smartctl id 5/197/198), which are notoriously **vendor-encoded** — drives pack
temperature/timestamps/other data into the raw column, so a non-zero
"uncorrectable" raw is a known false-CRIT source on healthy *consumer* drives,
not only on virtual SATA controllers (VMware/QEMU) and USB-SATA bridges. A
garbage raw → `UncorrectableErrors > 0` → false **CRIT "data loss risk"**.

Fix (mirrors §L exactly, no `--json` schema change):
- `sataSmartPlausible(dev)` — temp ∈ [-40,125]°C; reallocated/pending/uncorrectable
  sector counts ∈ [0, 10^8] (rejects 2^31/2^63 sentinels + packed-vendor garbage
  without suppressing any real failing drive, which is long dead by 10^5 bad
  sectors); power-on-hours ∈ [0, 10^6]. (`internal/analysis/heuristics_storage.go`)
- SATA loop: `SmartRead && !sataSmartPlausible(dev)` → route to a new
  "implausible SMART data — health unverified, values rejected" **WARN**, skip ALL
  scoring including `smart_status` (a drive reporting impossible attrs is an
  unreliable narrator of its own pass/fail).
- Fuzz: added `FuzzApplySATASmartJSON` over the `smartctl --json -a` parser
  (`applySATASmartJSON` had no fuzz; the NVMe `smart-log` parser already did) —
  1.6M execs, no panic. This is the §L "add an nvme smart-log fuzz sibling"
  defensive item, applied to the SATA JSON parser that was the actual gap.

Regression in `TestCheckNVMe` (`heuristics_container_drives_test.go`): garbage
SATA→WARN-not-CRIT; each trigger alone (temp/sectors/hours); smart-fail+garbage
attrs→WARN not a confident CRIT; and boundary guards proving a real uncorrectable
count still CRITs / real high temp still WARNs / a real smart_status fail still
CRITs. Validatable entirely offline (unit + fuzz, no hardware) — but the live
repro target is any VMware/QEMU guest with a SATA controller (the §L VCD node had
one) or a consumer drive with vendor-encoded id-198 raw.

| Item | Surface | Status |
|---|---|---|
| `sataSmartPlausible` bounds-gate before scoring | `heuristics_storage.go` | ✅ done |
| Implausible SATA read → WARN "values rejected", skip scoring | `checkNVMe` SATA loop | ✅ done |
| Fuzz `applySATASmartJSON` (smartctl JSON parser) | `fuzz_gpu_nvme_linux_test.go` | ✅ done (1.6M execs clean) |
| Regression: garbage→WARN, real failure still CRIT/WARN | `TestCheckNVMe` | ✅ done |

---

## R. GPU thermal implausible-value → false "thermal throttling" CRIT — ✅ DONE (fix/gpu-temp-plausibility-Q2, 2026-06-22)

The raw-tool implausible-value class (§L NVMe, §Q SATA) applied to **GPU
thermals**, found by an audit of which parsed numerics drive a verdict without a
plausibility gate. `readSysfsMilliC` (gpu_linux.go) reads hwmon `temp*_input` with
a bare `ParseInt/1000` and **no bounds check**, so a virtual GPU, a faulted
sensor, or a garbage/sentinel sysfs value surfaces as thousands of °C. Both
verdict paths then fired a false **CRIT**:
- `checkGPUDevice` (dsd health): `TempC >= 90` → "thermal throttling likely",
  `TempJunctionC >= 100` → "emergency thermal threshold".
- `gpuSummaryLine` + `gpuHints` (dsd gpu): same thresholds — a separate code path,
  so the bug existed in *both* (the cmd-verdict-drift footgun).

Fix (no `--json` schema change):
- **`GPUTempPlausible(c int)`** (exported, analysis) — reject temp ∉ [-40,150]°C.
  Real GPU silicon throttles then hard-shuts-down well below 150°C, so out-of-range
  is garbage, not an overheat. (0 is handled earlier by `GPUDeviceHasMetrics`.)
- Edge + junction blocks in `checkGPUDevice` gate on it → implausible reads emit a
  **WARN** "implausible temperature — thermal health unverified, reading rejected"
  and do NOT score the temp. Same gate wired into `gpuSummaryLine` (implausible →
  WARN, never CRIT, never a false "healthy") and `gpuHints` (no false emergency).
- Regression: `TestCheckGPU` (garbage edge/junction→WARN-not-CRIT, negative+real-
  metric→WARN, boundaries: real 105°C/110°C/150°C still CRIT) +
  `TestGPUSummaryLineImplausibleTemp` (cmd path: garbage→elevated not issue/healthy;
  real 105°C still CRIT). Both verdict paths now agree.

Offline-validatable (unit only). Live repro target: a GPU-passthrough/virtual
console DRM device, or any faulted hwmon sensor. Note: this is the false-CRIT
(implausibly-high) direction; the all-zero false-OK direction was §F (#383).

| Item | Surface | Status |
|---|---|---|
| `GPUTempPlausible` bounds-gate, exported, shared by both paths | `heuristics_hardware.go` | ✅ done |
| Gate edge+junction in `checkGPUDevice` → WARN not CRIT | `heuristics_hardware.go` | ✅ done |
| Gate `gpuSummaryLine` + `gpuHints` (close cmd-verdict drift) | `cmd/gpu.go` | ✅ done |
| Regression both paths (garbage→WARN, real overheat still CRIT) | `heuristics_round5_test.go`, `cmd/gpu_test.go` | ✅ done |

---

## S. Package security-scan starves on a cold cache → false-negative — ✅ DONE (fix/packages-rhel-rhui-scan-timeout + fix/disk-unreadable-smart, 2026-06-24)

Found live on a stock **AWS EC2 RHEL 10.2** box (`c7i-flex.large`, RHUI), cold
cache — the fresh-boot state warm laptop runs and self-written fixtures never
reproduce. Two false verdicts, both fixed and validated on the metal. Full
write-up: BUGS.md "AWS EC2 RHEL 10.2 — cold-cache validation".

| Item | Surface | Status |
|---|---|---|
| BUG-055 — cold `dnf updateinfo` (~6s over RHUI) blows the flat 8s `PackagesCollector` budget → false `could not verify security updates` (hid 8 criticals incl. kernel) or false `rpm --verify timed out`. Same class as the apt-side v1.8.1 #469 fix. | `internal/collectors/packages_linux.go` (`Timeout()` Deep-aware 20s/40s + 18s scan cap) | ✅ #476 |
| BUG-056 — `dsd disk` counted unreadable SMART (EBS, no nvme-cli) as a drive fault → false `WARN 1 disk concern(s)`, disagreeing with health (INFO). Sibling of BUG-050/048. | `cmd/disk.go` (`countDiskIssues` skips `SMART.Error != ""`), `cmd/disk_issues_test.go` | ✅ #477 |

Class to keep watching (audit play, not a task): any collector that runs a
slow refresh (package metadata, OVAL, remote probe) under a *shared* collector
deadline can starve a fast sibling check on a cold/slow host — reserve the fast
check's budget first (the pattern `pkgDBHealth` already follows), and size the
deadline for the cold-cloud case, not the warm-laptop one.

---

## T. RHEL 10 subscription undetected + RHUI false-alarm — ✅ DONE (fix/rhel-subscription-detect-and-rhui, 2026-06-24)

Same EC2 RHEL 10 box; surfaced while checking whether dsd detects Red Hat
Lightspeed/`rhc` enrollment (it does not — and a "not enrolled" warning was
deliberately NOT added: non-enrollment is a choice, not a fault). Two coupled
bugs, fixed together. Write-up: BUGS.md BUG-057.

| Item | Surface | Status |
|---|---|---|
| Detection gap — `subscription-manager` checked only at `/usr/bin`; RHEL 10 ships `/usr/sbin` (+`/sbin`) → Subscription collector silently skipped → an EXPIRED sub goes unwarned. | `internal/collectors/suseconnect_collector.go` (`subscriptionManagerPath()`) | ✅ #479 |
| RHUI false-alarm — fixing detection alone would WARN "not registered" on every AWS/Azure/GCP PAYG RHEL image (RHUI = updates work unregistered). | `suseconnect_collector.go` (`rhuiManaged()`, `unregistered-rhui`) + `heuristics_firmware.go` (OK case) + `heuristics_round7_test.go` | ✅ #479 |

Class note: binary-presence gates that hardcode `/usr/bin/<tool>` are fragile
across distro versions/`usr`-merge — prefer checking the real ship locations (or
`lookPath`). And any "not registered / not subscribed" verdict must be cloud-PAYG
(RHUI / PAYG marketplace) aware before it WARNs.

---

## U. zypper security scan false-negatives under the global zypp lock — ✅ DONE (security + integrity + kernel-reboot-sibling paths, fix/zypper-lock-retry-suse, 2026-06-24)

Found live on AWS EC2 **SLES 16.0** (first enterprise-SLES validation). zypper's
single global lock (`/run/zypp.pid`) + dsd's parallel collectors = a lock race;
the loser exits 7 (ZYPP_LOCKED) and was misreported as "could not verify (try
running as root)" — hiding 28 pending security patches, consistently, root and
non-root. Write-up: BUGS.md BUG-058. Same false-negative class as BUG-055 (RHEL
cold-cache scan).

| Item | Surface | Status |
|---|---|---|
| Security-update scan: retry on zypp-lock + accurate failure reason | `internal/collectors/packages_linux.go` (`collectZypper`, `zypperLocked`), `packages_linux_test.go` | ✅ #480 (live-validated 6/6) |
| **Integrity scan sibling** — `pkgIntegrityZypper` (`zypper verify`, deep mode) hit the same lock and read CLEAN on a lock error (deep-mode false-OK). Same retry guard applied; on a persistent lock it now sets `VerifyLocked` → INFO "could not verify package integrity", never silent clean. | `packages_linux.go`, `models/packages.go`, `heuristics_packages.go`, `heuristics_round6_test` | ✅ #481 (same mechanism as live-validated #480; sandbox is t4g-only, no SUSE box to re-validate) |
| **Kernel reboot-to-apply sibling (BUG-088)** — the #655 SUSE Kernel check keyed on `zypper needs-rebooting` STDOUT; under the same lock it exits 7 with empty stdout → the whole row was **silently dropped under root** (non-root never contended). Now keys on the exit code (0/102/7), retries the lock, and on a persistent lock sets `CheckUnverified` → INFO "could not be determined", never a drop or false "Kernel OK". | `maintenance_linux.go` (`suseRebootSignal`), `models/maintenance.go`, `heuristics_maintenance.go`, `maintenance_linux_test`, `falseok_signal_registry_test` | ✅ this PR — **live-validated on real SLES 16 (VMware vCD)**: 3× root runs Kernel OK restored; re-captured bundle records `needs-rebooting exit:0` |

Class note: any collector shelling a single-global-lock tool (`zypper`, `rpm`/`dpkg`
DB, `apt`) in dsd's parallel runner can lose a lock race → either retry on the
lock (preferred, as here / `rpmDBHealth`) or serialize that tool's callers. A
non-zero exit from such a tool must distinguish *locked* from *permission* from
*real failure* before the verdict text blames the user.

**Guard (post-BUG-088):** `collectors/zypper_lock_test.go::TestZypperCallsAreLockAware`
is a completeness tripwire (same idiom as `exec_locale_test.go`) — it enumerates every
`zypper` EXECUTION site and fails CI if a new one isn't registered in `zypperLockHandling`
with its lock strategy, forcing the author to retry-on-lock + decide on the exit code (not
stdout text) or document why it's lock-exempt. Registering the 9 existing sites surfaced
two non-urgent follow-ups (honest-degrade, NOT false-OK), both since confirmed fixed
(verified 2026-07-04 against the current code + the `zypperLockHandling` registry):
`cve_linux.go` `lp` (`checkCVEZypper`) now uses `runCmdOutput` (keeps the patch table
on a non-zero exit, same fix as #480), and `scanAllZypper` `list-patches`
(`health --cve`) is lock-retry-hardened (`runCmdCombined` + `zypperLocked` retry ×5,
mirroring `collectZypper`) — both registered in `zypper_lock_test.go`.

---

## W. Storage-HA collector audit 2026-06-28 — ✅ 10 fixed across 6 PRs

A 3-agent audit of the storage-HA collectors (ZFS/LVM/RAID · DRBD/multipath/iSCSI/HBA
· Ceph/Drives/IO/Disk) + live pve01/VM101 validation. Dominant theme: **non-root
false-verdicts** on root-gated storage sources — the run-as-both rule's target class.

- ✅ **Ceph non-root false-CRIT → INFO** (#598): unprivileged `ceph health` fails (admin
  keyring root-only) → was a false "cluster unreachable" CRIT on a healthy node. Live-
  validated on pve01 (dummy ceph.conf, old CRIT vs new INFO).
- ✅ **DRBD-9 non-root silent omission → needs-root INFO** + **iSCSI failed-session
  label** (#600): v9 netlink needs CAP_NET_ADMIN → returned nil (no row, hid split-
  brain); iSCSI inline read "N logged in" beside a CRIT icon.
- ✅ **Multipath non-root false-WARN** (#602): `IsMultipathPresent` only checked the
  binary; now gates on daemon-running OR sysfs `mpath-` maps. Live-validated on VM101.
- ✅ **`dsd disk` non-root false-OK** (#603): ignored ZFS/LVM `*ReadFailed` → printed
  "Disk healthy" while health said "could not verify". 3-way summary. Live on pve01.
- ✅ **ZFS SUSPENDED CRIT + double-scoring/verdict-flip** (#604): SUSPENDED state was
  absent from the switch (rendered green); ZFS scored by both DiskCollector and
  ZFSCollector with never-scrubbed INFO-vs-WARN flip. Live file-zpool old-vs-new.
- ✅ **HBA stale link-failure counter, NVMe unparseable hint, IO hotplug 100%-util**
  (#606): three edge/stale-signal false-alarms.

**iSCSI non-root degradation — ✅ FIXED (#612, 2026-06-29).** The deferral worry (that
iscsiadm doesn't fail non-root) was DISPROVEN live on VM101: with an *active* session,
non-root `iscsiadm -m session -P 1` fails on root-only per-session sysfs fields
(`session*/username`, 0400) with the SAME exit 21 as no-sessions — so an active session
was silently omitted non-root (a real false-OK). Discriminator: `/sys/class/iscsi_session/`
is world-readable, so its `session*` dir count tells "sessions present but need root"
(→ INFO) from "genuinely none" (→ silent). Live-validated old-vs-new. **Clean (verified):**
RAID/mdstat, LVM parsers, the prior SMART/image-fs/EBS gates; ZFS-installed-no-pools
"OK" is correct (like RAID-absent, no pools = nothing to fault).

---

## V. Audit + fleet sweep 2026-06-28 — ✅ 11 fixed (6 confirmed + 5 suspects)

A 3-agent false-OK audit of the recent Photon (#558–#582) + `dsd guest` (#555–#559)
batches plus a live pve01 fleet run (Ubuntu/Alma/Alpine/Arch LXCs + Debian/openSUSE
VMs, root & non-root). **6 confirmed bugs fixed** (#583 IO low-util false-CRIT, #584
vCPU-offline container false-WARN, #585 cgroupns=host false-OK, #587 net StuckLinks
render, #588 fstab nofail false-alarm, #589 vmware/guest "no host pressure" over-claim).
Clean: #556 layered view (presentational), #575 honesty flags, #564 docker/containerd/
tdnf, #567/#570/#577/#581 boot/storage guards, the root-vs-non-root invariant.

**The 5 deferred suspects were then all fixed too:**
- ✅ **networkd link-state gated on `/etc` config presence** — #593: `NetworkdAvailable()`
  falls back to `systemctl is-active systemd-networkd`, so a host with config in `/run`
  (netplan) or `/usr/lib` still gets the failed/stuck-link checks. Live-proven old-vs-new.
- ✅ **sshd@ suppression too broad** — #596: additive, fail-safe narrowing — after the
  blanket suppression, query `ExecMainStatus` and add back any `sshd@<conn>` instance
  that failed non-255 (a real per-connection fault); capped at 20. Both health +
  `services deep`.
- ✅ **ContainerGuest cgroup-v1 OOM/throttle gap** — #594 made it honest ("not
  measured"); **#615 now reads the real v1 counters** (cpu.stat / memory.oom_control via
  the resolved per-controller dirs, exposed as ContainerContext.CgroupV1MemDir/CPUDir),
  so a throttled/OOM-killed v1 container is actionably detected (WARN). CgroupV1Measured
  keeps it honest when the counter files can't be read. Unit-validated (no v1 host
  exists — modern distros default v2).
- ✅ **containerd "failed" display icon** — #591: renders CRIT, matching the verdict/exit.
- ✅ **PostBoot "unclean shutdown" on LXCs** — #592: `PostBootAvailable()` returns false
  in a container (prior-boot kernel forensics don't apply). Live-validated.

---

## Housekeeping

- **VMware Cloud Director T1 node** — 2026-06-18: first VMware-hypervisor guest
  (vcd-msk-3 tenant, Ubuntu 22.04, 192.168.30.10 behind Edge DNAT 5.35.120.132:2222).
  Six controller families exercised in one run via hot-added 1 GB disks:
  Paravirtual (PVSCSI), LSI Parallel (boot), LSI SAS, SATA, IDE, NVMe. Findings →
  §L (NVMe false-CRIT, the headline) + Systemd timeout entry; passing results:
  PVSCSI detection, empty-disk handling, and **root/non-root privilege-degradation
  honesty** (Hardening/KernelSec/Logs all degrade with explicit reason strings,
  no silent green). Add row to PLATFORM_COVERAGE.md (VCD/vSphere axis, NVMe-garbage
  path documented). VM left powered off in VCD to stop the PAYG meter; disks/config
  persist for revisit (PVSCSI-SMART parser re-test if §L fix needs a live target).
- **VMware coverage boundary — host-limit *active* paths GATED by tenant role.**
  The `user_adm` role on the vcd-msk-3 tenant exposes allocated memory/CPU but
  **not** the reservation/limit fields, so the limits can't be lowered below what
  the guest can reach, and a shared tenant gives no control over host memory/CPU
  pressure. Net: the *active* host-throttle conditions are not inducible here.
  - **Confirmed working (at-rest + no-throttle):** dsd correctly *detects* the
    limits exist (`cpu_limit_mhz:3000`, `mem_limit_mb:2048`, `balloon_loaded:true`,
    `balloon_mb:0`) and correctly does **not** false-alarm when they aren't being
    hit — under `stress-ng --cpu 1` the 3000 MHz limit on a 1-vCPU guest was never
    reached, `steal_pct` stayed 0, CPU check stayed OK. No false throttle alarm.
  - **GATED (needs limit-edit rights or a host you control):** active ballooning
    (`balloon_mb>0` → does dsd WARN and attribute it to *host reclamation* vs
    in-guest pressure?) and active CPU throttle (limit < 1 core → `steal_pct>0` →
    does dsd connect high steal to the known cpu_limit as "host-throttled"?). These
    are the §L-class "behave under the real condition" tests; the detection-at-rest
    half passes, the active half is unverified. Re-test on pve01 (own limits) or in
    a pilot's own vSphere where reservation/limit editing is available.
- **Methodology — root/non-root pair is now a standing check.** The 2026-06-18
  diff proved its worth: the NVMe false-CRIT (§L) was *invisible* in a non-root
  run (hidden behind "can't read") and only exposed under root. Every privileged
  collector gets a root + non-root run; non-root must degrade to an explicit
  "couldn't measure", never to OK. Fold into CLAUDE.md test matrix alongside the
  locale-safety and amd64-guest-on-ARM rules.
- **pve01 hardware-collector T1** — ✅ done 2026-06-16: HP ProDesk 600 G2 SFF
  (i7-6700 Skylake), PLATFORM_COVERAGE row 20. Fresh current-`main` dsd deployed
  and validated (hardware-smoke 6 pass / 1 skip). Confirmed the real **WD 1.8TB
  rotational HDD** SMART reads correctly on current code (temp 51°C, 36563h, attrs
  9/194) and types as HDD; SSD/HDD discrimination verified in `dsd disk`; verdicts
  sound. No defects found — the SSD temp=0/power-on=0 is accurate "not reported"
  (drive exposes no such attrs), logged as cosmetic under §E.4. No ECC/EDAC or
  IPMI (consumer SFF), so §B/server-grade gaps remain open.
- ~~BUGS.md: "Summary — Bugs by Category" + "Testbed Coverage" blocks are
  duplicated with diverging counts (13 vs 14) — delete the older pair.~~ ✅ DONE
  (2026-07-04) — removed the stale 13-bug pair, kept the current 14-bug one.

---

## S. Tenant-health command (`dsd guest`) — ✅ SHIPPED (container/VM auto-detect); v2 + cloud fold-in deferred

`dsd guest` (#559) unifies the per-platform guest commands into one auto-detecting
**tenant** command: container (Docker/Podman/LXC/k8s) → VM (VMware #555 / KVM #557) →
bare metal. Resolves the **innermost** layer first (a container on a VM reports as the
container, noting the VM beneath when DMI is visible — masked in hardened/OrbStack
containers, degrades honestly). Two-block guest-vs-host framing; verdict shares the
`dsd health` heuristic (cmd↔health guards added, §E). `dsd vmware`/`dsd kvm-guest` are
now `Hidden` specializations (out of `--help`, still functional; Cobra suggests
`guest`). Container view flags the "why is my container slow/dying" signals — cgroup
CPU-throttle (`nr_throttled/nr_periods`) + OOM-kills (`memory.events`). Live-validated:
a throttled Docker container (throttle 100% correctly flagged), real Proxmox VM 101
(healthy), bare-metal Mac. Pairing rule: `dsd kvm` = you run the hypervisor; `dsd guest`
= you're inside one.

**Open / deferred:**
- **v2 — multi-layer descent** (deferred, agreed): a container *on* a VM — attribute the
  constraint to the right owner (your cgroup quota vs the VM being CPU-starved by the
  hypervisor; container → VM → hypervisor → hardware, each layer's owner labelled). Same
  engine as the layered health view below. Demand/usability-driven.
- **Cloud guests fold-in**: extend `dsd guest` to AWS/Azure/GCP (collectors already
  exist — they fold into `dsd health` only today). Demand-gated (§C).
- **CRX / vSphere Pods (vSphere with Tanzu)** — DEMAND-GATED, build only if a customer
  runs it. CRX is VMware's live Photon-based micro-VM runtime for vSphere Pods (one
  container per paravirtual micro-VM). `dsd guest` likely already gives partial coverage
  (a vSphere Pod = container cgroups inside a VMware-DMI paravirtual VM, both of which it
  detects) — **validate on a real vSphere-Pod env before building anything bespoke**.
  Project Bonneville + Photon Platform explicitly OUT (EOL/discontinued, ~zero install
  base). The current VCD-tenant pilot is traditional IaaS, NOT Tanzu — so this is not its
  stack.
- **`dsd health --layered`** (#556, ✅ MERGED 2026-06-28 as the opt-in `--layered`
  flag): groups the flat health report into Hardware / Platform / OS layers led by a
  severity tally; KVMGuest/VMware/KVM-host/PVE/clouds sit in the Platform layer.
  Boundaries retuned so every health-registered collector maps to a layer (closed a gap
  where DBus + others fell into "Other"); CI-guarded. Non-breaking, `--json` untouched.
  Possible future follow-up (no demand yet): make it the default (`--flat` to opt out).
- **`dsd pve` node/guests/cluster tiering**: the Proxmox node-**operator** view (vs the
  guest/tenant view above) — "this node / your guests / cluster" tiers. NOT vmware's
  you-vs-provider split (a PVE node IS the provider). Proxmox = VMware-refugee market;
  deprioritized vs the VMware pilot.
- **#503 — GPU APU verification**: needs the user's AMD laptop (no cloud substitute) —
  the last unverified check from the v1.10.0 regression pass.
