# DashDiag — Backlog
# ─────────────────────────────────────────────────────────────────────────────
# Three sections: NOW (do this week) · NEXT (after NOW is done) · LATER (gated)
# Rule: NOW never has more than 10 items. When it empties, pull from NEXT.
# Update this file every time you complete something or discover something new.
# ─────────────────────────────────────────────────────────────────────────────

## STATUS
Last updated: 2026-05-08
Binary: dist/dsd ✅ (Go 1.26.3, all 4 platforms)
Sprints 0-4: ✅ COMPLETE
Code quality: ✅ CLEAN
  - golangci-lint: 0 issues
  - gosec: 0 issues (was 32)
  - govulncheck: 0 CVEs (was 2)
  - go test -short: 4.5s
  - Hooks: pre-commit + pre-push installed
Infrastructure: ✅ DONE
  - dependabot.yml, issue templates, PR template, JSON schema

---

## NOW — Do this week

### Code quality ✅ DONE
- [x] make tools installed
- [x] gofmt + goimports clean
- [x] golangci-lint 0 issues
- [x] gosec 0 issues
- [x] govulncheck 0 CVEs
- [x] testing.Short() skips — 4.5s short suite
- [x] make hooks installed

### Infrastructure ✅ DONE
- [x] .github/dependabot.yml
- [x] .github/ISSUE_TEMPLATE/ (bug + feature + config)
- [x] .github/PULL_REQUEST_TEMPLATE.md
- [x] schema/dsd-output.json + example-output.json
- [ ] Push to GitHub as public repo
- [ ] Set up branch protection (main requires CI — do immediately after push)

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
  Signal: "does it work with Docker?"

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
  Signal: "does it work with Kubernetes?"
- [ ] `dsd k8s deep` — BestEffort QoS, CPU throttling

### Gate: Phase 4 validated (k8s in use)
- [ ] `dsd pve` — Proxmox VE (cluster, ZFS, guests, kernel version)

### Gate: backend live (dashdiag.sh team accounts)
- [ ] `--badge` — README shields.io badge
- [ ] `dsd fleet` — enterprise multi-server management
- [ ] `--share` 90-day retention (free is 24h)

### Gate: 10+ paying teams
- [ ] UnpackOps RCA platform

### Gate: UnpackOps RCA validated
- [ ] Gauge (FinOps product)

---

## BUGS / KNOWN ISSUES

- [ ] `--qr` shows empty QR (shareURL stub until --share backend is built)
- [ ] `dsd health --weekly` shows "not enough data" until 7 real runs accumulate
- [ ] macOS: clock collector OffsetMs always -1 (by design — document it)
- [ ] `dsd services` empty state needs testing with actual config

---

## IDEAS (unscored — evaluate before moving to NEXT)

- Prometheus exporter: `dsd export metrics` scrape endpoint
- `dsd health --since 2h` — diff against baseline from N hours ago
- Man page generation from cobra docs
- Slack webhook: `dsd health --notify-slack $WEBHOOK_URL`
- `dsd health --threshold cpu_warn=90` — per-run threshold overrides
- Structured logging in --debug mode (JSON logs for aggregators)

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
