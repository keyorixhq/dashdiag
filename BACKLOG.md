# DashDiag — Backlog
# ─────────────────────────────────────────────────────────────────────────────
# Three sections: NOW (do this week) · NEXT (after NOW is done) · LATER (gated)
# Rule: NOW never has more than 10 items. When it empties, pull from NEXT.
# Update this file every time you complete something or discover something new.
# ─────────────────────────────────────────────────────────────────────────────

## STATUS
Last updated: 2026-05-08
GitHub: ✅ PUBLIC — github.com/keyorixhq/dashdiag
Tag: ✅ v0.1.1
Code quality: ✅ CLEAN (golangci-lint + gosec + govulncheck all 0)
Infrastructure: ✅ dependabot + issue templates + PR template + JSON schema
Branch protection: ✅ Active (Test ubuntu-22.04 + macos-14 required)
Linux testing: ✅ P1.1 COMPLETE (16/16) | ✅ P1.2 COMPLETE (12/12) | 🔄 P1.3 NEXT — Colima arm64

---

## NOW — P1.3 Colima arm64

### Infrastructure
- [ ] Run stress suite on Colima arm64 VM (P1.3)
- [ ] Update TESTING_PLAN.md with P1.3 results
- [x] Commit P1.2 + raw data fixes

---

## NEXT — After P1.3 complete

### Remaining Linux testing (TESTING_PLAN.md)
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
- CPU stress: FAIL on busy machines — mitigated by baseline skip + cores*2 spinners
- Swap stress: fixed 5GB was insufficient on high-RAM machines — now dynamic (150% free RAM)
- IO stress: LVM/tmpfs device detection — now follows mount chain to physical device
- macOS: clock OffsetMs always -1 (by design)
- Any container: Systemd Available=false (by design)

### Pre-existing
- [ ] `--qr` shows empty QR (shareURL stub)
- [ ] `dsd health --weekly` needs 7 days of data
- [ ] `dsd services` empty state needs real config testing

---

## BUGS FIXED

### P1.2 Proxmox + raw data (2026-05-08)
- [x] raw:{} empty in JSON output — all 12 collectors now serialise raw data
      Fix: added Raw field to JSONCheck, populated from r.Data
      Fixed: 2026-05-08
- [x] stress.sh IO test: writes to / root filesystem on LVM systems
      Fix: always write to /tmp/dsd_io_test, never to device mount point
      Fixed: 2026-05-08
- [x] stress.sh CPU: cores+2 spinners insufficient on 8-core machine → cores*2
- [x] stress.sh Swap: fixed 5GB allocation insufficient → 150% of free RAM
- [x] stress.sh IO: LVM/tmpfs device detection for iostat monitoring
- [x] run_stress.sh: sudo check fails on root-only environments (Proxmox)

### P1.1 Ubuntu 24.04 — Session 2 (2026-05-08)
- [x] CPU status shows FAIL — invalid status string in render layer
- [x] Zombie processes not detected — missing ProcessInfo case in ApplyThresholds
- [x] Disk threshold not triggering — Bfree vs Bavail
- [x] Network: packet loss, NIC DOWN, DNS failure not detected
- [x] Network: DNSFailed promotes check status to CRIT
- [x] FDLimits: insight check name fix + threshold 80→70%
- [x] FDLimits: resource.setrlimit inside Python for correct limit scope
- [x] stress.sh: 20 fixes (results counter, CPU spinners, iotop, timeouts, etc.)

### P1.1 Ubuntu 24.04 — Session 1 (2026-05-08)
- [x] Clock CRIT on Ubuntu 24.04 — NTPOffsetUsec removed
- [x] --plain and --json disagree on status
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
When someone requests a feature: add to IDEAS first, promote only after planning.
When a phase gate opens: move from LATER to NEXT (never directly to NOW).
Weekly review: 5 minutes — NOW accurate? anything stuck? IDEAS to promote?
