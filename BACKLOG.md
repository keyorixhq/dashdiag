# DashDiag — Backlog
# ─────────────────────────────────────────────────────────────────────────────
# Three sections: NOW (do this week) · NEXT (after NOW is done) · LATER (gated)
# Rule: NOW never has more than 10 items. When it empties, pull from NEXT.
# Update this file every time you complete something or discover something new.
# ─────────────────────────────────────────────────────────────────────────────

## STATUS
Last updated: 2026-05-08
Binary: dist/dsd ✅ (Go 1.26, all 4 platforms)
Sprints 0-4: ✅ COMPLETE
Code quality: ✅ CLEAN (golangci-lint 0 issues, gofmt applied)

---

## NOW — Do this week

### Code quality (before any public mention)
- [x] Run `make tools` — golangci-lint, gosec, govulncheck, staticcheck installed
- [x] Run `gofmt -w . && goimports -w ./...` — formatting applied
- [x] Run `golangci-lint run ./...` — 0 issues
- [ ] Run `gosec -quiet ./...` and fix any security findings
- [ ] Run `govulncheck ./...` and update any vulnerable deps
- [ ] Add `testing.Short()` skip to slow collectors (IO, swap, network, clock)
- [ ] Install pre-push hook: `make hooks`

### Infrastructure (before public launch)
- [ ] Add `.github/dependabot.yml` (auto dependency updates)
- [ ] Add `.github/ISSUE_TEMPLATE/` (bug report + feature request)
- [ ] Add `.github/PULL_REQUEST_TEMPLATE.md`
- [ ] Add `schema/dsd-output.json` — generate from `dsd health --json`
- [ ] Set up branch protection on GitHub (main requires CI to pass)
- [ ] Push to GitHub as public repo

### Verify on real Linux (critical — most dev was on macOS)
- [ ] SSH into a Linux server, copy binary, run `dsd health`
- [ ] Fix any Linux-specific issues (systemd, /proc paths, SELinux)
- [ ] Run `dsd health --json | python3 -m json.tool` on Linux
- [ ] Verify exit codes: `echo $?` after each command

---

## NEXT — After NOW is done

### Launch prerequisites
- [ ] Register dashdiag.sh domain
- [ ] Build dashdiag.sh landing page (single page, waitlist form)
- [ ] Add waitlist link to README.md
- [ ] Write README.md (demo GIF, install command, quick start)
- [ ] Record demo GIF with vhs or asciinema
- [ ] Write Hacker News Show HN post draft

### Features
- [ ] `dsd init` — wire into root.go so it runs on first launch
- [ ] `dsd health --share` — upload snapshot to dashdiag.sh (requires backend)
- [ ] `dsd health --badge` — README badge (requires backend)
- [ ] `--report --out <file>` — save markdown report to file
- [ ] Shell completion: `dsd completion bash/zsh/fish` (cobra built-in, 5 min)

### Quality
- [ ] Golden file tests for all renderers (`go test ./internal/render/... -update`)
- [ ] Contract tests in `test/contract/` — validate JSON output against schema
- [ ] Coverage report: `make cover` — identify packages under 70%
- [ ] Fuzz tests: `make test-fuzz` — verify all parsers are fuzz-resistant

### SDLC
- [ ] Write CHANGELOG.md (v0.1.0 entry minimum)
- [ ] cosign key generation for release binary signing
- [ ] Homebrew formula (Formula/dsd.rb in a tap repo)
- [ ] Install script (install.dashdiag.sh — curl | sh)

---

## LATER — Phase-gated (wait for the signal before building)

### Gate: dsd health is in daily use by real engineers
- [ ] `dsd health deep` — per-core CPU, temperature, throttle detection
  Signal: GitHub issue asking for per-core CPU detail

### Gate: first GitHub issue requesting containers
- [ ] `dsd docker` — container health, restart counts, OOM kills
  Signal: "does it work with Docker?" issue or Slack message

### Gate: dsd docker in production use
- [ ] `dsd compare` — multi-server side-by-side comparison
  Signal: "can you check multiple servers at once?"
- [ ] `dsd policy` — YAML policy file, CI gate (free tier)
  Signal: "can I fail CI if memory is too high?"

### Gate: Phase 3 validated (docker, compare in use)
- [ ] `dsd logs` — journald aggregation, recurring error detection
- [ ] `dsd security` — SSH config, sudo, listening ports, world-writable /etc

### Gate: dsd docker validated
- [ ] `dsd k8s` — 8 failure modes (OOMKilled, CrashLoop, Evicted, etc.)
  Signal: "does it work with Kubernetes?" (will come early)
- [ ] `dsd k8s deep` — BestEffort QoS, CPU throttling
  Signal: k8s power users asking for resource quota details

### Gate: Phase 4 validated (k8s in use)
- [ ] `dsd pve` — Proxmox VE (cluster, ZFS, guests, kernel version)
  Signal: Proxmox community requests

### Gate: backend live (dashdiag.sh team accounts)
- [ ] `--badge` — README shields.io badge with live health status
- [ ] `dsd fleet` — enterprise multi-server management
- [ ] `--share` 90-day retention (free is 24h)

### Gate: 10+ paying teams
- [ ] UnpackOps RCA platform (feeds on dsd --json output)

### Gate: UnpackOps RCA validated
- [ ] Gauge (FinOps product) — infrastructure cost + utilization transparency

---

## BUGS / KNOWN ISSUES

- [ ] `--qr` shows empty QR (shareURL stub until --share backend is built)
- [ ] `dsd health --weekly` shows "not enough data" until 7 real runs accumulate
- [ ] macOS: clock collector OffsetMs always -1 (by design — document it)
- [ ] `dsd services` empty state message needs testing with actual config

---

## IDEAS (unscored — evaluate before moving to NEXT)

- Prometheus exporter: `dsd export metrics` scrape endpoint
- `dsd compare --baseline` against a known-good server snapshot
- `dsd health --since 2h` — diff against baseline from N hours ago
- Man page generation from cobra docs
- Slack webhook: `dsd health --notify-slack $WEBHOOK_URL`
- `dsd health --threshold cpu_warn=90` — per-run threshold overrides
- Structured logging in --debug mode (JSON logs for log aggregators)

---

## DECISIONS LOG

2026-05  Rejected: AI flag (--ai) in collectors
         DashDiag is deterministic by design. AI analysis belongs in the
         UnpackOps platform which consumes --json output.

2026-05  Rejected: Persistent TUI dashboard (like btop)
         btop, lazydocker, k9s already exist. --watch flag covers the use case.

2026-05  Rejected: RPG-style achievement badges and skill trees
         Too gamey for DevOps/SRE audience. Streak tracking is sufficient.

2026-05  Rejected: Speed tier differentiation (free=slow, pro=fast)
         DashDiag runs locally — no server queues or compute tiers exist.

2026-05  Deferred: Watermarks on --share output
         Engineers would remove them. Subtle footer is the right approach.

---

## HOW TO USE THIS FILE

When you complete a NOW item: mark [x], pull from NEXT if NOW empties, commit.
When you find a bug: add to BUGS, escalate to top of NOW if blocking users.
When someone requests a feature: add to IDEAS, only promote after validation.
When a phase gate opens: move from LATER to NEXT (never directly to NOW).
Weekly review: 5 minutes — is NOW accurate, anything stuck, any IDEAS to promote?
