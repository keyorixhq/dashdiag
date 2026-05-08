# DashDiag — Backlog
# ─────────────────────────────────────────────────────────────────────────────
# Three sections: NOW (do this week) · NEXT (after NOW is done) · LATER (gated)
# Rule: NOW never has more than 10 items. When it empties, pull from NEXT.
# Update this file every time you complete something or discover something new.
# ─────────────────────────────────────────────────────────────────────────────

## STATUS
Last updated: 2026-05-08
GitHub: ✅ PUBLIC — github.com/keyorixhq/dashdiag
Tag: ✅ v0.1.1 (pending push)
Code quality: ✅ CLEAN (golangci-lint + gosec + govulncheck all 0)
Infrastructure: ✅ dependabot + issue templates + PR template + JSON schema
Branch protection: ✅ Active (Test ubuntu-22.04 + macos-14 required)
Linux testing: ✅ P1.1 COMPLETE (16/16) | 🔄 P1.2 NEXT — Proxmox host

---

## NOW — P1.2 Proxmox testing

### Infrastructure
- [ ] Tag and push v0.1.1
- [ ] Run stress suite on Proxmox host (P1.2)
- [ ] Update TESTING_PLAN.md with P1.2 results

---

## NEXT — After P1.2 complete

### Remaining Linux testing (TESTING_PLAN.md)
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

### Known limitations (not bugs)
- CPU stress test: FAIL on busy k8s nodes — baseline load dampens 1-min avg
  Mitigated: test now skips spinner phase if baseline already WARN/CRIT
- macOS: clock OffsetMs always -1 (by design — no timedatectl)
- Any container: Systemd Available=false (by design — no systemd in containers)

### Pre-existing
- [ ] `--qr` shows empty QR (shareURL stub)
- [ ] `dsd health --weekly` needs 7 days of data
- [ ] `dsd services` empty state needs real config testing

---

## BUGS FIXED

### P1.1 Ubuntu 24.04 — Session 2 (2026-05-08)
- [x] CPU status shows FAIL — invalid status string in render layer
- [x] Zombie processes not detected — missing ProcessInfo case in ApplyThresholds
      Fix: added checkProcesses + ProcessInfo case; parseProcStat already correct
- [x] Disk threshold not triggering — Bfree vs Bavail
      Fix: UsedPct uses Bavail; InodesUsedPct correctly uses Ffree (no reservation)
- [x] Network: packet loss not detected
      Fix: GatewayPacketLossPct ≥10% WARN, ≥50% CRIT; suppressed when NIC down
- [x] Network: NIC DOWN not detected
      Fix: PrimaryInterfaceDown=true when primary NIC flags exclude "up"
- [x] Network: DNS failure not detected + wrong status promotion
      Fix: DNSFailed bool + heuristics; DNSFailed promotes Network check to CRIT
- [x] FDLimits: insight check name was "FileDescriptors" → fixed to "FDLimits"
- [x] FDLimits: hot process threshold lowered 80% → 70%
- [x] FDLimits: test used prlimit on sudo wrapper; fixed to resource.setrlimit inside Python
- [x] stress.sh: CLEANUP_SERVICES empty → rm /etc/systemd/system (directory)
      Fix: [ -z "$svc" ] && continue guard
- [x] stress.sh: FDLimits check name wrong (was FileDescriptors)
- [x] stress.sh: CPU stress needs 30s wait on busy k8s nodes
- [x] stress.sh: results counter stuck at 0 — tee pipe creates subshell
      Fix: write PASS/FAIL/SKIP to temp file, read in cleanup_all
- [x] stress.sh: CPU spinners not killed after test — hang in full suite
      Fix: kill CLEANUP_PIDS inline after assert_status in test_cpu
- [x] stress.sh: get_check_status blocks indefinitely on slow network collectors
      Fix: timeout 15 wrapping dsd call
- [x] stress.sh: iotop hangs (interactive mode)
      Fix: iotop -aob -n 3
- [x] stress.sh: net_dns assertion wrong on Ubuntu 24.04 (stub resolver)
      Fix: mask/stop systemd-resolved instead of replacing resolv.conf
- [x] stress.sh: net_dns fails in --physical all due to NIC recovery dirty state
      Fix: sleep 5 after net_down + reorder to net_down → net_gateway → net_dns
- [x] stress.sh: CPU test FAIL on busy k8s baseline
      Fix: skip spinner phase if baseline already WARN/CRIT
- [x] stress.sh: test_disk moved to end of SSH_SAFE_TESTS for faster feedback

### P1.1 Ubuntu 24.04 — Session 1 (2026-05-08)
- [x] Clock CRIT on Ubuntu 24.04 — NTPOffsetUsec removed in systemd 245
      Fix: timedatectl timesync-status parsing as fallback
- [x] --plain and --json disagree on status (render layer computing own thresholds)
- [x] insights:[] in JSON when WARNs present
- [x] Exit code 0 when WARNs/CRITs present
- [x] Systemd false WARN on socket-activated units

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
