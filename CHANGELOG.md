# Changelog

All notable changes to DashDiag are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> Note: this file was not maintained between v0.2.0 and v0.6.8 — those releases
> are documented in [GitHub Releases](https://github.com/keyorixhq/dashdiag/releases)
> (auto-generated notes). Resumed at v0.6.9.

---

## [Unreleased]

### Fixed

- **`dsd tls`: an unreachable endpoint no longer reports "all healthy"** — a cert
  that couldn't be checked (unreachable remote endpoint, unreadable file) was
  counted in neither the CRIT/WARN/OK tally nor the exit code, so `dsd tls
  --endpoint down-host:443` printed "All 0 certificate(s) healthy" and **exited 0**
  — a cert-expiry monitor reporting success on a host it never reached (whose cert
  may be expired). `--json` was worse: the failed endpoint was dropped entirely
  (`0 expired, 0 expiring`). Now uncheckable certs are counted (`N ERR`, exit 1)
  and surfaced in `--json` as `uncheckable[]` with a `warning` status.
- **k8s: an unreachable cluster API no longer reads as a healthy cluster** — when
  `kubectl`/`k3s` is present but no cluster query succeeds (API server down, bad
  kubeconfig, or insufficient RBAC), every count stayed at zero and `dsd health`
  reported the cluster fine — a false-OK on the exact host where k8s is broken.
  It now tracks whether a query actually reached the API and surfaces
  "cluster health NOT verified" as INFO instead of a silent OK (matching how
  Docker/Ceph surface their unreachable states).
- **CVE scan: a failed apt scan no longer reads as "no CVEs"** — when both
  `apt-get --simulate upgrade`/`dist-upgrade` failed (apt lock held by
  unattended-upgrades, broken sources, or insufficient privilege), `dsd health
  --cve` parsed zero advisories and reported the system **clean** — a false sense
  of security on the most common Linux servers. apt now reports the failure (like
  the zypper/dnf paths already did), so a scan that couldn't run surfaces as INFO
  "CVE scan unavailable" instead of a green OK.

### Added

- **Release signing scaffold (minisign)** — `dsd update` can now verify that a
  release's `checksums.txt` was signed by the project key before trusting any hash
  in it, closing the self-updater single-origin gap (a compromised origin can
  serve a matching checksum but can't forge an Ed25519 signature). Verification is
  **in-binary** (stdlib + `x/crypto/blake2b`, no external tool) and **fails
  closed** once a key is embedded; `install.sh` adds a best-effort `minisign`
  check. The whole path ships **dormant** (like the Homebrew-tap job) until a
  maintainer generates a key and sets `MINISIGN_SECRET_KEY` — see
  `docs/RELEASE_SIGNING.md`. No behaviour change until then.

### Fixed

- **macOS: failing drives now surface, healthy drives stay quiet** — the `diskutil`
  SMART path had two faults: a `"Failing"` status was stuffed into an error field
  where the analysis layer *skips* it, so a dying Mac drive was silently hidden;
  and (after the SATA `SmartRead` guard) a healthy `"Verified"` drive was
  mis-labelled "SMART not read". Both darwin paths (`dsd health` + `dsd disk`) now
  share one verdict mapping: `Verified/Passed` → healthy, `Failing` → **CRIT**,
  `Not Supported`/unknown → "SMART not read" INFO.
- **SATA/SAS + `dsd hardware`: a drive whose SMART can't be read is no longer
  reported as failing** — `smartctl --json -a` emits JSON with **no `smart_status`**
  for drives behind RAID/HBA controllers, USB bridges, and virtual disks (common
  on cloud/VMware guests). The verdict then defaulted to "not passed" with no
  error, firing a false **CRIT** — `dsd health`: "drive may be failing"; `dsd
  hardware`: "may fail imminently, back up immediately" — on perfectly healthy
  drives. Both paths now track whether a verdict was actually read (`SmartRead`)
  and surface unread drives as **INFO** ("SMART health not read — behind a
  controller/bridge or virtual disk") instead of a confident CRIT. Brings SATA/SAS
  and `dsd hardware` in line with the NVMe path (BUG-048).
- **NVMe: a set `critical_warning` flag is no longer missed** — `nvme smart-log`
  prints `critical_warning` as hex (`%#x`, e.g. `0x4`), but the parser used
  `strconv.Atoi`, which can't read `0x…` and returned `0` — so a drive signalling
  spare-exhausted / reliability-degraded / read-only / backup-failed was reported
  **healthy** (`critical_warning` is *the* primary NVMe health flag). Now parsed
  base-0 (hex or decimal). Verified against the nvme-cli 2.13 format string.
- **NVMe/SMART: negative attribute values no longer read as a healthy drive** —
  the `nvme smart-log` and `smartctl -A` parsers assigned counts directly, so a
  garbled or hostile log printing e.g. `media_errors: -5` set a *negative* count
  — which slips under the `> 0` failure threshold in the analysis layer and reads
  as healthy (a false-OK). Both parsers now reject negative/garbled numbers.
  Found by the new `nvme`/`smartctl`/`rauc` fuzz harnesses (SSDLC Layer 2).
  NVMe key:value path of the `smartctl -A` parser assigned counts directly, so a
  garbled or hostile SMART log printing e.g. `Media and Data Integrity Errors: -5`
  set a *negative* `MediaErrors` count — which slips under the `> 0` failure
  threshold in the analysis layer and reads as healthy (a false-OK). The parser
  now rejects negative/garbled numbers (mirroring the SATA path's existing guard).
  Found by the new `smartctl`/`rauc` fuzz harnesses (SSDLC Layer 2).

### Security

- **Installer fails closed on unverifiable downloads** — `install.sh` previously
  *skipped* sha256 verification (silent warning, install continued) whenever
  `checksums.txt` couldn't be fetched, lacked an entry for the platform, or no
  hashing tool was present. An origin that simply withheld `checksums.txt` thus
  downgraded every install to unverified (threat model CLI **F-3**). The installer
  now **aborts** in those cases; the new `--no-verify` flag is the explicit, loud
  escape hatch for genuinely tool-less environments. A checksum *mismatch* still
  always aborts regardless of the flag. CI now guards the fail-closed path.

---

## [v0.8.7] — 2026-06-12

### Added

- **Checks reference (`docs/CHECKS.md`) + `dsd explain --markdown`** — a generated,
  browsable reference of all 36 checks (what each looks at, why it matters, how the
  verdict is decided, how to fix), so coverage is visible on GitHub without
  installing. A sync test keeps the doc from drifting from the topic registry;
  regenerate with `dsd explain --markdown > docs/CHECKS.md` (#197).

## [v0.8.6] — 2026-06-12

### Added

- **`dsd explain --search <keyword>`** — finds topics by content, not just name:
  `dsd explain --search memory` surfaces memory, swap, oom, docker, k8s, gpu, and
  sysctl. For "I'm seeing X, which check covers it?" when you don't know the topic
  name. Honors `--json` (#195).

## [v0.8.5] — 2026-06-12

### Added

- **`dsd explain` now covers 36 subsystems** — added oom, firewall, pve, bind,
  ceph, ipmi, bonding, and containerd, so the remaining commonly-flagged checks
  all have a "what it means / how it's judged / how to fix it" entry (#193).

## [v0.8.4] — 2026-06-12

### Added

- **`dsd explain --all`** — prints full detail for every topic in one pass; pipe
  it to a file for a complete checks reference (`dsd explain --all > checks.md`).
  Honors `--json`/`--plain`.
- **Tab-completion for `dsd explain`** — `dsd explain <TAB>` completes topic
  names (#191).

## [v0.8.3] — 2026-06-12

### Added

- **`dsd health --fix`** — after the verdict, prints a "Suggested fixes" block:
  the remediation commands for every flagged subsystem, grouped and deduped, as a
  copy-pasteable list. Completes the triage → understand → fix arc alongside
  `--explain`. Opt-in, so default output stays terse (#189).

## [v0.8.2] — 2026-06-12

The release that actually ships the SELinux path-guard security fix and the
prometheus output fix described in the v0.8.1 notes — both landed just after the
v0.8.1 tag, so v0.8.2 is the first built binary to contain them. Plus a CI
lint cleanup.

### Security

- **SELinux policy-type path hardening** — now shipped in a released binary. (Full
  detail under v0.8.1; in short: the filesystem path built from `SELINUXTYPE=` in
  `/etc/selinux/config` is charset-guarded before use. Root-owned config, so
  practical exploitability was low.)

### Changed

- **CI: golangci-lint gate is clean** — cleared 18 pre-existing issues so the
  stricter gate passes: removed dead, unreferenced helper funcs (and the
  single-func `fcntl_linux.go`); preallocated slices with known capacity; dropped
  ineffectual assignments; applied two staticcheck simplifications; and `nolint`'d
  two inherently-branchy parsers plus a gosec G703 on a host-local trusted crontab
  path (stat-only). Behaviour-preserving (#187).

### Docs

- `dsd examples` adds scenarios for understanding a finding (`dsd explain` /
  `--explain`), monitoring integration (`--nagios` / `--prometheus`), and watching
  an incident (`--watch`) (#184).

## [v0.8.1] — 2026-06-12

### Added

- **`dsd explain` now covers 28 subsystems** — added sysctl, entropy, fdlimits,
  thermal, kvm, lvm, raid, and nfs to the offline reference, so the common checks
  an operator gets flagged on all have a "what it means / how it's judged / how to
  fix it" entry (#182).

### Security

- **SELinux policy-type path hardening** — `dsd health`/security collection built
  a filesystem path from the `SELINUXTYPE=` value in `/etc/selinux/config` under a
  suppression that claimed allowlist validation the code did not actually enforce.
  The value is now charset-guarded before use. The config file is root-owned, so
  practical exploitability was low, but the guard is now enforced in code. As a
  side effect, distro-custom policy names (e.g. Debian's `default`) are handled
  correctly.

### Fixed

- Prometheus exposition output now uses `fmt.Fprintf` directly instead of
  `WriteString(fmt.Sprintf(...))` (no behavioural change; resolves two
  staticcheck warnings).

### Docs

- README documents the v0.7–v0.8 features: `dsd explain`, and the `dsd health`
  `--watch` / `--explain` / `--nagios` / `--prometheus` flags, with a
  monitoring-integration section (#181).

## [v0.8.0] — 2026-06-12

Monitoring integration and in-context explanations.

### Added

- **`dsd health --nagios`** — a single-line monitoring-plugin status on stdout
  (`DASHDIAG OK/WARNING/CRITICAL - …`) with the exit code already matching the
  Nagios spec (0/1/2). Drops dsd straight into Nagios/Icinga/check_mk/Sensu as a
  check command, no wrapper script. Each affected subsystem is named once at its
  worst level (#178).
- **`dsd health --prometheus`** — the verdict as Prometheus exposition metrics
  (`dsd_up`, `dsd_check_status{check="…"}`, `dsd_health_status`; severity 0/1/2)
  for node_exporter's textfile collector or scraping — chart and alert on host
  health in Grafana/Alertmanager. Output validated by `promtool check metrics`
  (#179).
- **`dsd health --explain`** — after the verdict, appends a "Why these matter"
  block explaining each flagged subsystem and how to fix it (from the `dsd explain`
  content). Opt-in, so default output stays terse (#177).

## [v0.7.0] — 2026-06-12

Two new capabilities — a live incident view and an in-tool reference.

### Added

- **`dsd explain <topic>`** — a plain-language reference for the health checks.
  `dsd explain swap` (or zfs, cve, drives, docker, k8s, …) prints what the check
  diagnoses, why it matters, how dsd decides severity (the real thresholds), and
  the commands to investigate and fix it; no argument lists the 20 topics, and
  aliases resolve (`ram`→memory, `zpool`→zfs, `kev`→cve). It is pure static
  documentation — it never touches the host — and `--json` is supported. Turns dsd
  from an alerter into a teacher: when health flags a subsystem, get the full
  picture in-tool (#174, #175).
- **`dsd health --watch` change detection** — each refresh now prints a "Changes
  since last refresh" block: 🆕 newly-broken, ✅ newly-resolved, and ↕ severity
  changes (WARN→CRIT), with "· no change" as a steady-state signal. Insights are
  matched across ticks by a value-normalized signature, so a fluctuating number
  (CPU 75%→82%) doesn't churn as resolved+new. The point of watch during an
  incident is the delta — now you see it (#173).

## [v0.6.15] — 2026-06-11

### Fixed

- **cve: apt no longer claims a CVSS verdict it can't measure.** apt publishes no
  per-package CVSS, so `dsd health --cve` inferred severity from the package name
  yet reported it as "critical advisory — CVSS >= 9.0" / "high-severity — CVSS >=
  7.0" — and a name guess (e.g. a routine `python3-*` or `libssl` update) could
  raise a hard CRIT. For apt, name-matched advisories now fold into a single
  honest WARN ("severity inferred from package name; apt exposes no CVSS", with a
  pointer to the distro security tracker) — no name-only CRIT, no fabricated CVSS
  claim. Package managers that expose real severity (dnf/zypper/…) are unchanged,
  and CISA KEV matches still escalate to CRIT (#171).

## [v0.6.14] — 2026-06-11

A batch of false-positive fixes — verdicts that fired on healthy hosts.

### Fixed

- **swap: no more false WARN on zram churn.** Swap-activity WARNed on *any*
  paging (`> 0` pages/s) and ignored zram. On zram-by-default distros
  (Fedora/Ubuntu/Pop!_OS/SteamOS) swapping is compressed-RAM churn, not disk
  thrash. The WARN floor is raised to 50 pages/s, and zram-backed paging below the
  heavy-thrash threshold is now INFO ("compressed RAM, not disk thrash"). Heavy
  paging (>100 pages/s) still CRITs; disk-backed swap keeps WARN/CRIT (#167).
- **drives: power-on-hours is age, not wear.** The NVMe (>35,000 h) and HDD
  (>43,800 h) power-on-hours checks WARNed about "consumer/HDD lifespan" — but
  hours run is not a failure signal, and the real endurance metrics
  (NVMe percentage-used/spare, SATA reallocated sectors, SMART self-assessment)
  are checked separately. A healthy long-lived enterprise drive no longer gets a
  false lifespan WARN; power-on-hours is now INFO context (#168).
- **zfs: no more perpetual CRIT on repaired vdev errors.** `zpool`'s cumulative
  read/write/checksum vdev counters include errors ZFS already repaired and
  persist until `zpool clear`, so one transient blip CRITed forever. Severity is
  now gated on actual pool health: an ONLINE pool with a clean last scrub is WARN
  ("repaired; investigate if recurring"), CRIT only when the pool is not ONLINE or
  the last scrub left unrepairable errors — real corruption is still caught (#169).

## [v0.6.13] — 2026-06-11

A follow-up to v0.6.12 closing the matching display drift.

### Fixed

- **network: `dsd net --deep` now agrees with `dsd health`.** v0.6.12 rate-normalized
  the since-boot TCP counters in the health verdict, but the standalone
  `dsd net --deep` table and its issue tally still classified those same counters
  by raw absolute value — so it could show ⚠️/❌ and count an "issue" for a lone
  historical SYN-retransmission/listen-overflow that `dsd health` correctly reports
  as INFO. Both now read a single shared classifier (`analysis.DeepTCPCounterLevel`),
  so the two views can't diverge (same single-source approach as the v0.6.11 disk
  fix). The counter table is relabeled "cumulative since boot." Verified live on an
  8-day-uptime host (149 SYN retransmissions → INFO, Network OK).

## [v0.6.12] — 2026-06-11

A bug-fix and hygiene release continuing the false-verdict cleanup.

### Fixed

- **network (false CRIT on long uptime)** — the since-boot TCP counters
  (SYN retransmissions, listen-queue overflows, retransmit failures) were read
  as raw totals, so a single old spike on a long-uptime host produced a current
  WARN/CRIT. They are now rate-normalized against uptime: a sustained rate
  escalates, while a small historical total — or one that can't be rated because
  uptime is unknown — is reported as INFO with the "not necessarily ongoing"
  boundary surfaced.

### Changed

- **internal: zero golangci-lint issues.** Fixed the `.golangci.yml` v2 schema
  (test-file exemptions had been silently inactive since the v2 upgrade),
  refactored `rpmvercmp` and `checkPackages` for clarity, and replaced a
  deprecated `parser.ParseDir` call. No behavioural change; CVE version-compare
  behaviour is pinned by tests and verified identical.

## [v0.6.11] — 2026-06-10

A correctness-and-coverage batch: a few targeted features plus continued
false-OK / phantom-verdict fixes across collectors.

### Added

- **arm64 awareness** — CPU core identification on arm64 and an arch-aware GRUB
  check (no x86-only assumptions) (#158).
- **Fleet Team-mode nudge** — multi-host `dsd fleet` runs surface a tasteful
  waitlist nudge for the forthcoming Team mode (#154).
- **Package update freshness** — `dsd packages` marks an "up to date" verdict as
  *unverified* when the package manager's update metadata is stale, instead of
  asserting health it can't confirm (#163).

### Fixed

- **health (non-systemd)** — DBus and journald checks are gated on systemd, so
  Alpine/OpenRC hosts no longer raise a phantom CRIT (#162).
- **disk capacity** — `dsd disk` capacity verdicts are aligned to `dsd health`
  from a single source, eliminating divergent thresholds (#161).
- **timeline** — dmesg events are classified by kernel log level rather than
  keyword matching, reducing mis-severity (#160).
- **drives (false-OK)** — NVMe drives are no longer reported "healthy" when SMART
  was never read (#159).
- **logs** — pstore panic records are recency-gated so a single old panic no
  longer produces a perpetual CRIT (#157).
- **health (memory/crash)** — sub-GB total memory no longer renders "0 GB"; a
  stale crash-loop is no longer presented as live (#156).
- **install** — the documented `--prefix` flag is honored, with wget and
  `--prefix` now covered in CI (#155).

## [v0.6.10] — 2026-06-09

### Fixed

- **Gated-collector false-OK sweep** — three more error states that were silently
  hidden now surface:
  - **Ceph**: a node configured for a cluster (`/etc/ceph/ceph.conf` present) whose
    mons are unreachable now reports CRIT instead of staying silent (#145).
  - **cloud-init**: an errored/degraded instance is now flagged — `cloud-init
    status` exits non-zero to report state and still prints the status JSON, which
    was previously discarded (#146).
  - **IPMI**: a failed BMC/sensor read on a server with IPMI hardware now WARNs
    instead of being swallowed by the not-available early return (#146).

## [v0.6.9] — 2026-06-09

A fleet-wide review closing a recurring **false-OK** bug class — a green/OK verdict
(or silence) shown when a check had not actually verified health.

### Fixed

- **Unified verdict visibility** across live `dsd health`, `--report`, and
  `--json`/`--yaml`: not-applicable collectors no longer appear as phantom "✅ OK"
  rows. Backed by a shared `runner.IsAvailable` contract + AST meta-test (#131, #132).
- **Disk/SMART**: a FAILING drive (smartctl exits non-zero on "DISK FAILING") is no
  longer silently skipped — the "back up immediately" CRIT now fires (#138).
- **Docker**: container OOM kills are no longer missed on hosts with >10 die/kill
  events in the window (#140).
- **PVE**: a never-backed-up VM is no longer hidden by a healthy node-wide backup
  age (#143).
- **Security drift**: added/removed SSH config drop-ins are now detected, not just
  content changes (#137).
- **TLS**: a cert that expired <24h ago is classified expired, not "expires in 0
  days" (#136).
- **CVE**: "scan unavailable" surfaces as INFO instead of a green CVE OK (#135).
- **Timeline**: journal parsing hardened — no false CRITs from a missing PRIORITY,
  no dropped non-UTF-8 MESSAGE events, rune-safe truncation (#134).
- **k8s**: most-recent warning events are shown (was oldest), and a malformed line
  no longer aborts event collection (#141).
- **BIND**: no phantom "named not answering" when `dig` isn't installed (#142).
- **LVM**: classic-snapshot origin no longer misread as the volume size (#139).
- **Collectors**: message truncation is rune-safe — no split UTF-8 in verdict lines
  (#144).

### Changed

- **`dsd fleet --json`** now returns a fleet-level rollup object
  (`{verdict, exit_code, total, counts, hosts}`) mirroring `dsd health --json`,
  instead of a bare array. Consumers using `jq '.[]'` should switch to `.hosts[]`
  (#133).

## [v0.2.0] — 2026-05-10

### Added

- **`--debug` flag** — enables structured debug logging to stderr for
  troubleshooting silent failures and slow checks. Output is independent
  of the configured output mode (`--json`, `--yaml`, `--plain`) so machine-
  readable stdout stays clean. Format: `[debug] HH:MM:SS.mmm  Component
  message  key=value`. Debug logging covers:
  - Per-collector start, finish, duration, and error from `internal/runner`
  - Network probe trace from `internal/collectors/network_quick.go`:
    gateway detection, each ICMP attempt (host, mode, error), TCP fallback
    attempts, final probe results
  See `internal/debug/` package for the API. Disabled by default — zero
  overhead when off.

- **F0 — inline drill-down on WARN/CRIT.** When a check fires WARN or CRIT,
  DashDiag now automatically gathers and displays the relevant attribution
  data inline:
  - **Memory**: top processes by RSS
  - **CPU**: top processes by CPU%
  - **Swap**: top processes by VmSwap (Linux)
  - **Disk**: largest directories on the affected mount
  - **IO**: top processes by I/O bytes/sec (Linux)
  - **Network**: TCP states by process, gateway ping latency/jitter
  - **Processes**: zombies with their parent process info
  - **Systemd**: last 20 lines of journalctl for failed units
  - **FDLimits**: top processes by FD usage as % of their limit
  - **Clock**: chronyc tracking output (Linux) or sntp output (macOS)
  - **Sysctl**: current value vs recommended for failing keys
  - **KernelSecurity**: AppArmor profiles in complain mode, SELinux denials
  
  Healthy systems are unaffected — drill-down code only runs on WARN/CRIT.
  Wall time on a healthy system stays at ~1.3s. Wall time when something is
  wrong adds ~0.5-1s for attribution work.
  
  Drill-down output appears in both terminal and `--json` formats.
  Use `--terse` to skip drill-down and see only the verdict.

- **`models.NetworkInfo.ICMPBlocked`** field (JSON: `icmp_blocked`,
  omitempty). Set to `true` when DashDiag had to fall back from ICMP
  probes to TCP probes for L3 reachability — typically when running
  as a non-root user on a system with restrictive
  `net.ipv4.ping_group_range`. Surfaces this fact for future privilege-
  aware UX messaging.

### Breaking changes

- **`--json` output**: check name `"MACPolicy"` renamed to `"KernelSecurity"`.
  Scripts that filter on `checks[].name == "MACPolicy"` must be updated.
  The underlying JSON fields inside the `raw` object are unchanged
  (`se_linux_present`, `se_linux_mode`, `se_linux_denials`, `app_armor_present`, `app_armor_mode`).

### Changed

- Renamed `MACPolicy` collector, model, and all internal references to `KernelSecurity`.
  The `MAC` prefix collided with macOS naming conventions and confused users on Mac
  (macOS does not implement Mandatory Access Control via SELinux/AppArmor).
- **Systemd and KernelSecurity now report INFO instead of OK when not applicable.**
  On systems without systemd (Alpine, OpenWrt, most Docker containers, macOS) the
  Systemd check now shows `INFO  systemd not present on this system` rather than
  `OK`. Same change for KernelSecurity when no kernel security module is enforcing.
  Previous behaviour would silently report OK and mislead users into thinking these
  subsystems were healthy when they weren't even running.
- **Errored collectors now surface as INFO insights** instead of being silently
  dropped. Previously, if a collector returned a non-nil error from `Collect()`,
  the analysis layer would silently skip it (`continue`) and the user would see
  *nothing* — indistinguishable from a passing check. Now any collector error
  produces an INFO insight: `<Check> check could not run — <error>`. Covers
  permission denials (`opening diskstats: permission denied`), context timeouts,
  missing system files, and any future collector failure mode.

### Fixed

- **Network check false-positive "gateway unreachable" for non-root Linux users.**
  The `go-ping` library required either `CAP_NET_RAW` or a permissive
  `net.ipv4.ping_group_range` (Ubuntu's default `1 0` blocks unprivileged
  ICMP). Both ICMP modes failed silently for typical non-root users,
  returning 100% packet loss — which heuristics interpreted as gateway
  CRIT. Discovered on real-hardware testing (2011 MacBook running Ubuntu
  24.04). Would have triggered for ~every `curl install.sh | sh` user
  on launch.
  
  Fix: added a TCP-connect fallback in `pingRTT`. When both privileged
  and unprivileged ICMP fail, DashDiag now tries TCP dial to ports 53
  and 80 — *both successful connection AND `connection refused` count
  as L3 reachability proof*, since the host responded to the packet.
  No `CAP_NET_RAW` required; works under every Linux distribution's
  default settings.

- **Gateway probe ambiguity for routers that ignore probes (e.g. Zyxel
  Keenetic).** Previously, any condition that produced `GatewayPingMs <
  0` triggered a CRIT "gateway unreachable" alert — even when the
  internet itself was clearly reachable. Some consumer routers drop
  ICMP/TCP probes on the LAN interface while still forwarding traffic
  normally. The analysis now distinguishes:
  - Both gateway *and* internet unreachable → CRIT "host appears offline"
  - Gateway silent but internet reachable → INFO "gateway not responding
    to probes — internet traffic is flowing"
  - Both reachable → normal latency thresholds apply

- **F0 drill-down didn't render in non-TTY contexts** — `internal/render/health.go`
  gated drill-down rendering on `mode == ModeHuman`, but `output.DetectMode`
  returns `ModePlain` whenever stdout is not a TTY (Docker without `-t`, CI/CD
  pipelines, shell pipes, redirected output). Extended the condition to
  `ModeHuman || ModePlain`. Lipgloss strips ANSI codes automatically in non-TTY
  contexts, so output stayed clean.

- **`SwapInfo.ZramUsedPct` field was always zero.** The field existed in
  the model since v0.1 but was never populated — a silent zero. Now reads
  `/sys/block/zramN/disksize` and `mm_stat` field 0 (`orig_data_size`)
  across all zram devices and calculates utilisation percentage.
  Graceful: if `mm_stat` is unavailable, the field stays zero.

- **SELinux insight orphaned by check-name mismatch.** SELinux insights
  used `Check: "SELinux"` but the renderer attached drill-down via prefix
  match against `"KernelSecurity"`. The drill-down was generated correctly
  but never displayed. Renamed the insight to `"KernelSecurity"` so prefix
  matching attaches the drill-down output.

---

## [v0.1.1] — 2026-05-08

### Fixed

- **macOS false positives**: devfs virtual mounts no longer show as full disks;
  clock sync now detected via `pgrep timed` (no sudo required on Ventura+);
  `somaxconn` threshold skipped on macOS (Linux-only concept);
  zombie detection column order fixed (`ps axo pid,ppid,stat,comm`);
  Memory/Swap insights show macOS-specific commands (`vm_stat`, `sysctl vm.swapusage`).
- **Colima/Lima VMs**: `/mnt/lima-*` disk mounts excluded; cloud-init systemd units
  (`cloud-final`, `cloud-config`, `cloud-init`, `cloud-init-local`) filtered from
  failed-unit list.
- **Clock in containers**: NTP check skipped when running inside a container
  (clock is inherited from the host).
- **FDLimits**: hot-process threshold lowered from 80% to 70% to reduce false negatives.
- **JSON output**: raw collector data included under `raw` key in each check object.
- **Network**: `probeConnectivity` extracted to fix `funlen` lint; DNS lookup has a
  dedicated 5 s sub-context timeout.
- **Heuristics**: `FDLimits` check name corrected (was `FileDescriptors`).

### Added

- Stress test suite (`scripts/stress/`) with self-calibrating CPU, swap, and IO tests;
  supports physical and SSH-safe test modes.

---

## [v0.1.0] — 2026-04-28

### Added

- Initial release.
- Collectors: CPU, Memory, Swap, Disk, IO, Network, Clock, FDLimits, Processes,
  Systemd, Sysctl, KernelSecurity (SELinux / AppArmor).
- Renderers: terminal health table (`dsd health`), JSON (`--json`), TUI (`--tui`).
- Analysis: threshold-based insights with per-check remediation hints.
- Platform detection: bare-metal, VM, container context awareness.
- CI: golangci-lint, gosec, govulncheck, dependabot, branch protection.
