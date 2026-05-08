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
Linux testing: ✅ P1–P4 COMPLETE | macOS arm64: ✅ VALIDATED

---

## NOW — Launch prerequisites

- [ ] Register dashdiag.sh domain
- [ ] Build dashdiag.sh landing page (single page + waitlist form)
- [ ] Write README.md (install command, quick start, demo output)
- [ ] Record demo GIF with vhs or asciinema
- [ ] Add waitlist link to README, push
- [ ] Write Hacker News Show HN post draft
- [ ] Write CHANGELOG.md (v0.1.0 + v0.1.1 entries)

---

## NEXT — After first HN post

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
- [ ] cosign key generation for release binary signing
- [ ] Homebrew formula (Formula/dsd.rb in a tap repo)
- [ ] Install script (install.dashdiag.sh — curl | sh)

### Testing (deferred)
- [ ] P2.8 Flatcar — requires registry authentication
- [ ] P5.1 Fedora 40, P5.2 Oracle Linux 9, P5.3 AlmaLinux 9
- [ ] AWS Graviton EC2 — real arm64 server hardware
- [ ] Raspberry Pi OS
- [ ] macOS Intel (x86_64) validation
- [ ] macOS stress suite — needs native macOS version (networksetup, pfctl, launchctl)
      Linux stress.sh uses tc/ip/systemctl — not portable to macOS

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
- IO stress: no iostat in Colima Lima VM — graceful skip expected
- Flatcar: registry access denied — deferred
- macOS: clock OffsetMs always -1 (by design — no offset API without sudo)
- Any container: Systemd Available=false (by design)
- Memory WARN in 512MB containers — slab cache threshold fires (expected)

### Pre-existing
- [ ] `--qr` shows empty QR (shareURL stub)
- [ ] `dsd health --weekly` needs 7 days of data
- [ ] `dsd services` empty state needs real config testing

---

## BUGS FIXED

### macOS validation (2026-05-08)
- [x] Disk CRIT /dev (devfs) — macOS virtual filesystem false positive
      Fix: exclude devfs and /System/Volumes/* from disk collector
- [x] Clock CRIT on macOS — timedatectl/chronyc not available
      Fix: check timed daemon running (macOS time sync service)
- [x] Sysctl CRIT net.core.somaxconn — Linux-only sysctl on macOS
      Fix: skip somaxconn check on darwin
- [x] Processes WARN zombie false positive on macOS
      Fix: use ps axo pid,stat on darwin, check only stat column for Z
- [x] Swap/Memory hints wrong on macOS (free -h, vmstat don't exist)
      Fix: macOS-appropriate hints (vm_stat, sysctl vm.swapusage, top -l 1)

### P1.3 Colima + Docker distro sweep (2026-05-08)
- [x] Clock CRIT in all containers — inherit host clock fix
- [x] Disk CRIT /mnt/lima-cidata — Lima metadata disk excluded
- [x] Systemd CRIT cloud-final.service — cloud-init services excluded

### P1.2 Proxmox + raw data (2026-05-08)
- [x] raw:{} empty in JSON — all 12 collectors serialise raw data
- [x] stress.sh IO: writes to / on LVM, CPU cores*2, Swap 150% free RAM
- [x] run_stress.sh: conditional sudo for root-only environments

### P1.1 Ubuntu 24.04 — Sessions 1+2 (2026-05-08)
- [x] 25 bugs fixed — see git log for full details

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
Weekly review: 5 minutes — NOW accurate? anything stuck? Ideas to promote?
