# DashDiag — Backlog
# ─────────────────────────────────────────────────────────────────────────────
# Three sections: NOW (do this week) · NEXT (after NOW is done) · LATER (gated)
# Rule: NOW never has more than 10 items. When it empties, pull from NEXT.
# Update this file every time you complete something or discover something new.
# ─────────────────────────────────────────────────────────────────────────────

## STATUS
Last updated: 2026-05
Binary: dist/dsd ✅ (Go 1.26, all 4 platforms)
Sprints 0-4: ✅ COMPLETE

---

## NOW — Do this week

### Code quality (before any public mention)
- [ ] Run `make tools` to install golangci-lint, gosec, govulncheck, staticcheck
- [ ] Run `gofmt -w . && goimports -w ./...` and commit formatting
- [ ] Run `golangci-lint run ./...` and fix every issue
- [ ] Run `gosec -quiet ./...` and fix security findings
- [ ] Run `govulncheck ./...` and update any vulnerable deps
- [ ] Add `testing.Short()` skip to slow collectors (IO, swap, network, clock)
- [ ] Install pre-push hook: `make hooks`

### Infrastructure (before public launch)
- [ ] Add `.github/dependabot.yml` (auto dependency updates)
- [ ] Add `.github/ISSUE_TEMPLATE/` (bug report + feature request)
- [ ] Add `.github/PULL_REQUEST_TEMPLATE.md`
- [ ] Add `schema/dsd-output.json` (public JSON contract — generate from `dsd health --json`)
- [ ] Set up branch protection on GitHub (main requires CI to pass)
- [ ] Push to GitHub as public repo

### Verify on real Linux (critical — most dev was on macOS)
- [ ] SSH into a Linux server, copy binary, run `dsd health`
- [ ] Fix any Linux-specific issues (systemd, /proc paths, SELinux)
- [ ] Run `dsd health --json | python3 -m json.tool` on Linux
- [ ] Verify exit codes: echo $? after each command

---

## NEXT — After NOW is done

### Launch prerequisites
- [ ] Register dashdiag.sh domain
- [ ] Build dashdiag.sh landing page (single page, waitlist form)
- [ ] Add waitlist link to README.md
- [ ] Write README.md (proper one — demo GIF, install command, quick start)
- [ ] Record a demo GIF (use vhs or asciinema — show dsd health output)
- [ ] Write the Hacker News Show HN post draft

### Features
- [ ] `dsd init` — wire into root.go so it runs on first launch
- [ ] `dsd health --share` — upload snapshot to dashdiag.sh (requires backend)
- [ ] `dsd health --badge` — README badge (requires backend)
- [ ] `--report --out <file>` — save markdown report to file
- [ ] Weekly report accumulates real data after 7+ days of use

### Quality
- [ ] Golden file tests for all renderers (run `go test ./internal/render/... -update`)
- [ ] Contract tests in `test/contract/` — validate JSON output against schema
- [ ] Coverage report: `make cover` — check which packages are under 70%
- [ ] Fuzz tests: `make test-fuzz` — verify all parsers are fuzz-resistant

### SDLC
- [ ] Write CHANGELOG.md (at minimum, v0.1.0 entry)
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
  Signal: engineer asks "can I check multiple servers at once?"
- [ ] `dsd policy` — YAML policy file, CI gate (free tier)
  Signal: engineer asks "can I fail CI if memory is too high?"

### Gate: Phase 3 validated (docker, compare in use)
- [ ] `dsd logs` — journald aggregation, recurring error detection
- [ ] `dsd security` — SSH config, sudo, listening ports, world-writable /etc

### Gate: dsd docker validated
- [ ] `dsd k8s` — 8 failure modes (OOMKilled, CrashLoop, Evicted, etc.)
  Signal: "does it work with Kubernetes?" (this will come early)
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
  The AI-assisted root cause analysis product

### Gate: UnpackOps RCA validated
- [ ] Gauge (FinOps product) — infrastructure cost transparency
  Uses dsd utilization data + cloud billing APIs

---

## BUGS / KNOWN ISSUES
<!-- Add issues here as you find them. Move to NOW when you fix them. -->

- [ ] `--qr` shows empty QR because shareURL is not yet implemented (stub)
- [ ] `dsd health --weekly` shows "not enough data" until 7 real runs accumulate
- [ ] macOS: clock collector OffsetMs always -1 (by design, but document it)
- [ ] `dsd services` empty state message needs testing with actual config

---

## IDEAS (unscored — evaluate before moving to NEXT)
<!-- Dump ideas here. Do not move to NEXT until you have validated the need. -->

- Prometheus exporter: `dsd export metrics` (scrape endpoint)
- `dsd compare --baseline` against a known-good server snapshot
- Shell completion: `dsd completion bash/zsh/fish`
- `dsd health --since 2h` — compare against baseline from N hours ago
- Man page generation from cobra docs
- Slack webhook integration: `dsd health --notify-slack $WEBHOOK_URL`
- `dsd health --threshold cpu_warn=90` — per-run threshold overrides
- Structured logging in --debug mode (JSON logs for log aggregators)

---

## DECISIONS LOG
<!-- Record why you chose NOT to build something. Prevents re-litigating. -->

2026-05  Rejected: AI flag (--ai) in collectors
         Reason: DashDiag is deterministic by design. AI analysis belongs in
         UnpackOps platform which consumes --json output. Keeps dsd fast and offline.

2026-05  Rejected: Persistent TUI dashboard (like btop)
         Reason: btop, lazydocker, k9s already exist. DashDiag is a snapshot tool.
         --watch flag covers the "keep it running" use case without becoming a daemon.

2026-05  Rejected: RPG-style achievement badges and skill trees
         Reason: Too gamey for DevOps/SRE audience. Streak tracking and milestones
         provide habit formation at the right intensity.

2026-05  Deferred: Watermarks on --share output
         Reason: Engineers would remove them from shared outputs, defeating the
         viral mechanic. Subtle footer instead ("Generated by DashDiag").

2026-05  Deferred: Speed tier differentiation (free=slow, pro=fast)
         Reason: DashDiag runs locally. No server queues or compute tiers exist.

---

## HOW TO USE THIS FILE

**When you complete a NOW item:**
  1. Mark it [x]
  2. If NOW is now empty, pull 3-5 items from NEXT into NOW
  3. git commit -m "docs: update backlog"

**When you discover a bug:**
  Add it to BUGS. If it is blocking users, move to top of NOW immediately.

**When someone requests a feature:**
  Add it to IDEAS first. Evaluate demand before committing to NEXT.
  Move to NEXT only when: (a) multiple people have asked, or (b) it clearly
  serves the product strategy in SPEC.md.

**When a phase gate opens:**
  Check the gate condition. If it is met, move the item from LATER to NEXT.
  Never move LATER items directly to NOW — they need scoping first.

**Weekly review (5 minutes):**
  Is NOW accurate? Is anything stuck? Do any BUGS need escalating?
  Should any IDEAS be promoted? Should any NEXT items be deprioritised?
