## STATUS
Last updated: 2026-05-08
GitHub: ✅ PUBLIC — github.com/keyorixhq/dashdiag
Tag: ✅ v0.1.0 @ 5dec280
Code quality: ✅ CLEAN (golangci-lint + gosec + govulncheck all 0)
Infrastructure: ✅ dependabot + issue templates + PR template + JSON schema
Branch protection: ✅ Active (Test ubuntu-22.04 + macos-14 required)
Linux testing: ✅ P1.1 COMPLETE — Ubuntu 24.04 MacBook | 🔄 P1.2 NEXT — Proxmox host
Current binary: v0.1.0-2-g071ef0a-dirty (deployed to 192.168.10.10)

---

## NOW — Linux testing bugs (fix before launch)

### Remaining stress suite issues (P1.1 Ubuntu 24.04)
- [ ] FD exhaustion test: FDLimits=OK (expected WARN or CRIT) — collector not triggering
      System FD usage shows 3232/9223372036854775807 — per-process limit not per-system
      Need to investigate how dsd reads FD limits vs what the test is exhausting
- [ ] net_dns: still fails in --physical all run (state cache from previous test)
      Passes when run individually. Cache clear in get_check_status may not fire
      in right order when tests run sequentially in same process
- [ ] CPU stress: FAIL on this k8s machine when baseline load already high
      Known limitation — k8s background processes dampen 1-min load average signal
      Not a collector bug — acceptable on busy nodes

### Infrastructure (before public launch)
- [x] Branch protection set up
- [x] Pushed to GitHub as public repo
- [ ] Commit and push all fixes from current session
- [ ] Tag v0.1.1 after P1.1 complete

## NEXT — After P1.1 complete

### Remaining Linux testing (TESTING_PLAN.md)
- [ ] P1.2 Proxmox host
- [ ] P1.3 Colima arm64 VM
- [ ] P2.1–P2.8 Docker distro sweep (Rocky, Debian, Alpine, SUSE, Flatcar...)
- [ ] P3.1–P3.4 arm64 Docker sweep
- [ ] P4.1–P4.2 Container context tests

### Launch prerequisites (do in this order)
- [ ] Register dashdiag.sh domain
- [ ] Build dashdiag.sh landing page (single page + waitlist form)
- [ ] Write README.md (install command, quick start, demo output)
- [ ] Record demo GIF with vhs or asciinema
- [ ] Add waitlist link to README, push
- [ ] Write Hacker News Show HN post draft

### Features
- [ ] `dsd init` — wire into root.go so it runs on first launch
- [ ] `dsd health --share` — upload snapshot to dashdiag.sh (requires backend)
- [ ] `--report --out <file>` — save markdown report to file
- [ ] Shell completion: `dsd completion bash/zsh/fish` (cobra built-in, 5 min)

### Quality
- [ ] Golden file tests for all renderers (`go test ./internal/render/... -update`)
- [ ] Contract tests in `test/contract/` — validate JSON output against schema
- [ ] Coverage report: `make cover` — identify packages under 70%

### SDLC
- [ ] Write CHANGELOG.md (v0.1.0 + v0.1.1 entries)
- [ ] cosign key generation for release binary signing
- [ ] Homebrew formula (Formula/dsd.rb in a tap repo)
- [ ] Install script (install.dashdiag.sh — curl | sh)

---

## LATER — Phase-gated (wait for the signal before building)

### Gate: dsd health is in daily use by real engineers
- [ ] `dsd health deep` — per-core CPU, temperature, throttle detection

### Gate: first GitHub issue requesting containers
- [ ] `dsd docker` — container health, restart counts, OOM kills

### Gate: dsd docker in production use
- [ ] `dsd compare` — multi-server side-by-side comparison
- [ ] `dsd policy` — YAML policy file, CI gate (free tier)

### Gate: Phase 3 validated
- [ ] `dsd logs` — journald aggregation, recurring error detection
- [ ] `dsd security` — SSH config, sudo, listening ports

### Gate: dsd docker validated
- [ ] `dsd k8s` — 8 failure modes (OOMKilled, CrashLoop, Evicted, etc.)
- [ ] `dsd k8s deep` — BestEffort QoS, CPU throttling

### Gate: Phase 4 validated
- [ ] `dsd pve` — Proxmox VE (cluster, ZFS, guests, kernel version)

### Gate: backend live
- [ ] `--badge` — README shields.io badge
- [ ] `dsd fleet` — enterprise multi-server management
- [ ] `--share` 90-day retention

### Gate: 10+ paying teams
- [ ] UnpackOps RCA platform

### Gate: UnpackOps RCA validated
- [ ] Gauge (FinOps product)

---

## BUGS / KNOWN ISSUES

### Active — stress suite
- [ ] FD exhaustion — see NOW above
- [ ] net_dns in --physical all — see NOW above
- [ ] CPU stress on busy k8s node — see NOW above

### Pre-existing
- [ ] `--qr` shows empty QR (shareURL stub)
- [ ] `dsd health --weekly` needs 7 days of data
- [ ] macOS: clock OffsetMs always -1 (by design)
- [ ] `dsd services` empty state needs real config testing

---

## BUGS FIXED

### P1.1 Ubuntu 24.04 — Session 2 (2026-05-08)
- [x] CPU status shows FAIL — invalid status string in render layer
      Fixed: 2026-05-08
- [x] Zombie processes not detected — missing ProcessInfo case in ApplyThresholds
      Fix: added checkProcesses function + ProcessInfo case
      Fixed: 2026-05-08
- [x] Disk threshold not triggering — Bfree vs Bavail
      Fix: switched UsedPct to Bavail; InodesUsedPct correctly uses Ffree
      Fixed: 2026-05-08
- [x] Network: packet loss not detected
      Fix: GatewayPacketLossPct ≥10% WARN, ≥50% CRIT; suppressed when NIC down
      Fixed: 2026-05-08
- [x] Network: NIC DOWN not detected
      Fix: PrimaryInterfaceDown=true when primary NIC flags exclude "up"
      Fixed: 2026-05-08
- [x] Network: DNS failure not detected
      Fix: DNSFailed bool + heuristics; DNSFailed promotes Network status to CRIT
      stress.sh: mask systemd-resolved for Ubuntu 24.04 stub resolver
      Fixed: 2026-05-08
- [x] stress.sh cleanup: rm /etc/systemd/system errors on empty CLEANUP_SERVICES
      Fix: [ -z "$svc" ] && continue guard
      Fixed: 2026-05-08
- [x] stress.sh FDLimits name wrong (was FileDescriptors)
      Fixed: 2026-05-08
- [x] stress.sh CPU stress needs 30s wait on busy k8s nodes
      Fixed: 2026-05-08
- [x] stress.sh results counter stuck at 0 (subshell via tee pipe)
      Fix: write PASS/FAIL to temp file, read in cleanup_all
      Fixed: 2026-05-08
- [x] stress.sh --physical all hangs — CPU spinners not killed after test
      Fix: kill CLEANUP_PIDS inline after assert_status in test_cpu
      Fixed: 2026-05-08
- [x] stress.sh --physical all hangs — get_check_status blocks on network collector
      Fix: timeout 15 wrapping dsd call in get_check_status
      Fixed: 2026-05-08
- [x] stress.sh iotop hangs (interactive mode)
      Fix: iotop -aob -n 3
      Fixed: 2026-05-08
- [x] stress.sh net_dns assertion wrong — resolv.conf replace ineffective on Ubuntu 24.04
      Fix: mask/stop systemd-resolved instead
      Fixed: 2026-05-08

### P1.1 Ubuntu 24.04 — Session 1 (2026-05-08)
- [x] Clock CRIT on Ubuntu 24.04 — NTPOffsetUsec removed in systemd 245
      Fix: timedatectl timesync-status parsing as fallback
      Fixed: 2026-05-08
- [x] --plain and --json disagree on status
      Fix: render layer no longer computes own thresholds
      Fixed: 2026-05-08
- [x] insights:[] in JSON when WARNs present
      Fixed: 2026-05-08
- [x] Exit code 0 when WARNs/CRITs present
      Fixed: 2026-05-08
- [x] Systemd false WARN on socket-activated units
      Fixed: 2026-05-08

---

## IDEAS

- Prometheus exporter: `dsd export metrics`
- `dsd health --since 2h` — diff against N hours ago
- Man page generation from cobra docs
- Slack webhook: `dsd health --notify-slack $WEBHOOK_URL`
- `dsd health --threshold cpu_warn=90` — per-run threshold overrides
- Structured logging in --debug mode

---

## DECISIONS LOG

2026-05  Rejected: AI flag in collectors — deterministic by design
2026-05  Rejected: Persistent TUI dashboard — btop/lazydocker/k9s exist
2026-05  Rejected: RPG achievements — too gamey for DevOps/SRE audience
2026-05  Rejected: Speed tier differentiation — runs locally, no server queues
2026-05  Deferred: Watermarks on --share — engineers would remove them

---

## HOW TO USE THIS FILE

When you complete a NOW item: mark [x], pull from NEXT if NOW empties, commit.
When you find a bug: add to BUGS, escalate to top of NOW if blocking.
When someone requests a feature: add to IDEAS first, promote only after validation.
When a phase gate opens: move from LATER to NEXT (never directly to NOW).
Weekly review: 5 minutes — NOW accurate? anything stuck? IDEAS to promote?
