# DashDiag — Backlog
# ─────────────────────────────────────────────────────────────────────────────
# Three sections: NOW (do this week) · NEXT (after NOW is done) · LATER (gated)
# Rule: NOW never has more than 10 items. When it empties, pull from NEXT.
# Update this file every time you complete something or discover something new.
# ─────────────────────────────────────────────────────────────────────────────

## STATUS
Last updated: 2026-05-10 (afternoon, end of session 2)
GitHub: ✅ PUBLIC — github.com/keyorixhq/dashdiag
Tag: 🟡 v0.1.1 in git (v0.2.0 code complete + uncommitted; needs Network bug fix before tag)
Code quality: ✅ CLEAN (golangci-lint + gosec + govulncheck all 0 as of last check)
Tests: ✅ ALL GREEN (full suite passes including 6 new weekly tests, 4 new heuristics tests)
Linux testing: ✅ P1–P4 + Fedora 40 ARM64 + Alpine 3.21 ARM64/amd64
              + 2011 MacBook Ubuntu 24.04 with Kind cluster + zram
macOS arm64: ✅ VALIDATED on dev machine

F0 inline drill-down: ✅ SHIPPED + END-TO-END VERIFIED 2026-05-10
   - Fedora docker testing covered 9/12 checks; 3 bugs fixed this session
   - Real-hardware testing on 2011 MacBook surfaced privilege issue (below)
   - Drilldown bug fixed: renderer now respects ModePlain (Docker, CI, pipes)

🔴 LAUNCH BLOCKER FOUND TODAY: Network check false-positives "gateway
   unreachable" when run as non-root user on Linux. See NOW section.
   Caught by real-hardware testing on 2011 MacBook before launch.
   Estimated fix: 2-3 hours (Option B graceful degrade) or
   half-day (Option A TCP connect probe replacement).
   Must fix before launch — else every "curl install.sh" user sees
   false-positive Network CRIT on first run.

🔴 TESTING BLIND SPOT IDENTIFIED: Today's bug was the first non-root
   Linux test in the project's history. All previous testing surfaces
   (unit tests, CI, Mac, Docker tests as root) masked the issue.
   Other checks likely have similar non-root degraded behaviour we
   haven't observed yet. See NEXT/Testing section for matrix expansion
   plan: per-distro × {root, normal user, CAP_NET_RAW} × all 12 checks.
   This pairs with the systematic error-handling refactor — together
   they eliminate the silent-failure category that produced 6 bugs
   in the past 2 days.

---

## NOW — Launch prerequisites

- [x] **Inline drill-down on WARN/CRIT** ✅ SHIPPED 2026-05-09
      See "F0 shipped" section in BUGS FIXED for full implementation details.
- [x] ✅ **F0 drilldown not firing end-to-end** — RESOLVED 2026-05-10.
      Root cause was NOT a stale binary (as initially suspected). The
      drilldown data was populated correctly by drilldown.PopulateAll all
      along. The bug was in the renderer:
      
        internal/render/health.go gated drilldown table rendering on
        `r.mode == output.ModeHuman`, but output.DetectMode returns
        ModePlain whenever stdout is not a TTY — which is always the case
        in Docker without -t, CI/CD pipelines, shell pipes, and any
        redirected output.
      
      Fix: extended the render condition to `ModeHuman || ModePlain`.
      Lipgloss strips ANSI codes automatically in non-TTY contexts, so
      renderDetails already produced clean plain text — just needed to
      be allowed to run in ModePlain.
      
      Verified in Fedora 40 ARM64 docker:
      - Terminal mode: Memory CRIT shows "Top processes by memory (RSS)"
        table inline with PID/MEM%/RSS/COMMAND columns
      - --json mode: details field present with type "process_table",
        full columns and rows (was unaffected — JSON skips PrintAll entirely)
      
      Lesson: integration testing in production-like environments (Docker
      without -t, CI runners, redirected output) catches bugs that unit
      tests and interactive Mac terminal testing both miss.
- [ ] ~~JSON output contaminated with progress logs~~ — FALSE ALARM. The test
      command used `2>&1` which merged stderr into stdout. Code in
      internal/output/progress.go correctly uses fmt.Fprintf(os.Stderr, ...)
      for all progress messages. Without `2>&1`, JSON output is clean.
- [ ] 🔴 **LAUNCH-BLOCKING: Fix Network check false-positive for non-root users.**
      Discovered 2026-05-10 testing on real 2011 MacBook with Ubuntu 24.04:
      manual `ping 192.168.10.1` succeeds 4/4 with 0.6ms RTT, but
      `dsd health` (run as user andrei) reports Network CRIT
      "gateway is unreachable" simultaneously.
      
      Root cause: internal/collectors/network_quick.go uses go-ping
      library which needs either CAP_NET_RAW (raw ICMP) or the user's
      GID inside net.ipv4.ping_group_range (unprivileged ICMP via UDP).
      Ubuntu default: `net.ipv4.ping_group_range = 1 0` which means
      no groups can use unprivileged ICMP. So both code paths fail
      for non-root users, returning 100% packet loss, which heuristics
      interprets as "gateway unreachable" → CRIT.
      
      Confirmed with `sysctl net.ipv4.ping_group_range` → "1 0" and
      `id` → uid=1000 gid=1000 (outside the empty allow-range).
      
      Why this is launch-blocking: every user installing via
      "curl install.sh" runs as their normal user. Almost all Linux
      distros ship with restrictive ping_group_range. So almost
      everyone evaluating DashDiag at launch will see false-positive
      Network CRIT on first run. Looks broken to engineers reviewing
      the tool. Will damage the launch.
      
      Fix options (combination of A+B recommended):
      A) Replace ICMP ping with TCP connect probe to gateway port 53
         or 80. No privilege needed. Works on every Linux. Slightly
         different semantic ("is gateway providing service" rather
         than "is gateway alive") but arguably more useful.
      B) When both ping paths fail, detect the privilege failure
         specifically (errno EPERM or similar) and emit a different
         INFO message: "ICMP unavailable to non-root user (Network
         check skipped — run with sudo for full network diagnostic)"
         instead of CRIT "gateway unreachable".
      C) Document: install instructions can suggest
         `sudo setcap cap_net_raw=ep ~/bin/dsd` to grant capability
         without requiring full root.
      
      Minimum fix for launch: Option B (~2-3 hours). Stops false-positive
      from looking like real alarm.
      Better fix: Option A (~half day). Actually solves the problem.
- [ ] Decide and commit DashDiag license (Apache 2.0 recommended — see PRODUCT_IDEAS.md)
      Once decided, write LICENSE file in repo root and update README.md
      license footer accordingly. README currently states Apache 2.0.
- [ ] Register dashdiag.sh domain
      README currently references https://dashdiag.sh/install.sh as the install
      command. Until domain exists, the install line in README is broken.
      Either register first OR temporarily change install instructions to
      point at github.com/keyorixhq/dashdiag/releases.
- [ ] Build dashdiag.sh landing page (single page + waitlist form)
- [x] Write README.md ✅ DRAFTED 2026-05-10
      ~210 lines, structure: hero → install → usage → checks table →
      why → how it works → output formats → examples → status →
      license/contributing/about. F0 drilldown shown in hero example.
      
      Open review items before final ship:
      - [ ] Replace invented Memory CRIT example output with real output
            captured from a production-like system, OR keep as illustrative
            (current state). Real output makes the README more authentic.
      - [ ] Resolve dashdiag.sh URL question — register domain first, OR
            change install command to github releases URL until domain exists
      - [ ] Resolve Keyorix link in About footer — currently links to
            keyorix.com which may not exist or may be aimed at the secrets
            manager. Decide: link now, remove link, or use plain text.
      - [ ] Verify license footer matches actual LICENSE file once written
      - [ ] Read top to bottom for voice / honesty / accuracy issues
      - [ ] Decide on examples section depth — currently 3 examples, could
            add: dramatic before/after with CPU pegged, JSON-driven script,
            --diff between snapshots
      - [ ] After demo GIF is recorded, embed at top of README (replace or
            supplement the text example block in hero)
- [ ] Record demo GIF with vhs or asciinema (after drill-down ships)
      Now unblocked — F0 verified end-to-end on Fedora 40 ARM64.
      The wow moment to capture: Memory CRIT firing → top processes
      table appearing inline. After GIF is recorded, embed in README
      hero section.
- [ ] Add waitlist link to README, push
- [ ] Write Hacker News Show HN post draft
- [ ] Write CHANGELOG.md (v0.1.0 + v0.1.1 entries)
- [ ] Backup strategic documents to private GitHub repo
      (keyorixhq/strategy, private). Today.
      See "Strategy backup setup" section at bottom of this file
      for the 5-minute setup commands and ongoing sync workflow.
      Risk: 8 documents (~3000 lines) currently exist only on one laptop.
- [🟡] **Testing MacBook deployment — in progress.** Binary deployed at
      `/home/andrei/bin/dsd` on 2011 MacBook (192.168.10.10) running
      Ubuntu 24.04 with Kind cluster + zram. Smoke test successful
      (12 checks run in 1.0s, F0 drilldown verified, KernelSecurity
      INFO behaviour confirmed correct).
      
      Discovered the launch-blocking Network privilege bug during smoke
      test (see above).
      
      **Plan: parallel root + andrei cron jobs** — provides direct
      comparison dataset of privilege-sensitive code paths over 7 days.
      Run both simultaneously every 6 hours. Compare state.json at end
      of week to see exactly which checks differ between privilege levels.
      Higher signal than single-user cron data alone.
      
      Setup (after Network bug fix + redeploy):
        ssh andrei@192.168.10.10
        crontab -e
        # add: 0 6,12,18,23 * * * /home/andrei/bin/dsd health > /dev/null 2>&1
        sudo crontab -e
        # add: 0 6,12,18,23 * * * /home/andrei/bin/dsd health > /dev/null 2>&1
      State accumulates in /home/andrei/.dsd/state.json (user) and
      /root/.dsd/state.json (root). Diff after a week reveals all
      privilege-sensitive code paths empirically.
      
      Optional: start parallel cron BEFORE Network fix. Pre-fix data
      becomes the empirical baseline showing exactly what the bug
      looked like; post-fix data shows the improvement directly.

---

## NEXT — After first HN post

### Features
- [ ] `dsd init` — wire into root.go so it runs on first launch
- [ ] `dsd health --share` — upload snapshot to dashdiag.sh (requires backend).
      Full design captured in docs/SHARE_DESIGN.md (2026-05-10). Includes
      decisions on public-vs-private links (public default, password opt-in),
      retention (7d free, 30-90d paid), pricing model (freemium), what data
      is sensitive in shares, and trigger conditions for prioritizing the
      build. Estimated 2-3 weeks of focused work for minimal v0.3 backend.
      Flags currently hidden from --help (cmd/root.go) until backend ships.
- [ ] `--report --out <file>` — save markdown report to file
- [ ] Shell completion: `dsd completion bash/zsh/fish` (cobra built-in, 5 min)
- [ ] **`dsd hardware` — diagnostics for aged & degrading hardware (deferred, 2026-05-10).**
      
      Strategic rationale: The vast majority of running infrastructure globally
      is aged hardware on extended life cycles — Spanish small business, Eastern
      European hosting, Indian datacentres on 8-year-old Dells, Brazilian
      universities, NHS Trusts on 2014 boxes, African ISPs. Hardware shortage
      worldwide means this is the default, not the edge case. Cloud-native
      monitoring tools serve none of these users well. SMART monitoring exists
      (smartd, Netdata exporters) but requires assembly — not a `curl install.sh`
      experience. DashDiag's identity ("instant, no-agent, no-setup") fits this
      gap perfectly.
      
      Why deferred (not built now): These users are real but hard to monetise
      — small business, public sector, regions where EUR pricing is a meaningful
      chunk of monthly salary. Sprint 1-4 monetisation targets DevOps/SRE/platform
      engineers at companies with ops budgets. Build for paying users first,
      ship, get first paying customer, *then* expand. Aged-hardware operators
      become the open-source community-builder layer in a HashiCorp/GitLab/MongoDB
      "we serve everyone, but enterprises pay" model.
      
      Scope sketch (v0.3 or v0.4):
      - `dsd hardware` (fast): SMART summary via smartctl --json if installed,
        thermal from /sys/class/thermal, ECC count from EDAC. Non-root where
        possible. <500ms.
      - `dsd hardware deep`: full SMART attribute dump, lm-sensors readings,
        thermal history, vendor-specific drive health.
      - Hint integration in `dsd health`: when disk wear or thermal looks
        suspicious, suggest "run `dsd hardware` for details".
      - Runtime dependency: smartmontools (graceful degrade if missing).
      
      Identity question to revisit when prioritising: does this expand DashDiag
      from "system health for ops engineers" toward "diagnostics for the
      infrastructure that's actually running the world"? That's a sharper market
      position but a real repositioning — affects landing page, HN angle, target
      audience.

- [ ] 🔴 **i18n architecture for DashDiag v0.3 (committed, 2026-05-10).**
      
      Source of truth: COMPANY_PRINCIPLES.md § Principle 2. The principle
      requires i18n architecture mandatory from v1.0 in every product.
      DashDiag v0.3 is the first public release — the architecture
      commitment binds at v0.3.
      
      Launch language set (per principles, native-speaker reviewed):
      - English (default)
      - Spanish — founder + Spanish-speaking friends review panel
      - Russian — founder native
      - Chinese (Simplified) — trusted friend reviewer
      
      Languages beyond launch set arrive via community pull requests with
      public credit (JetBrains / VLC / Linux model). No machine-translated
      fallbacks. Bad translation worse than no translation.
      
      Realistic scope (≈3-5 days focused work):
      
      Phase 1 — Library + extraction (1-2 days):
      - Choose i18n library. Candidates: golang.org/x/text/message (stdlib-
        adjacent, plural rules built in), nicksnyder/go-i18n (mature, large
        ecosystem), or hand-rolled map[string]map[string]string (simplest).
        Decision: lean toward go-i18n unless plural complexity is low
        enough that stdlib suffices.
      - Extract all user-facing strings into internal/i18n/messages/<locale>.toml
        (or .json/.yaml depending on library).
      - String inventory targets: internal/analysis/heuristics.go (insights),
        internal/render/*.go (output), cmd/*.go (cobra help text),
        internal/tips/*.go (tip messages), internal/drilldown/*.go.
      
      Phase 2 — Plumbing (1 day):
      - Pass *i18n.Localizer through render layer.
      - All Sprintf calls converted to Localize(messageID, args).
      - Verify --json / --yaml stay English (machine contract per principles).
      - Verify --debug logs stay English (diagnostic contract per principles).
      
      Phase 3 — Detection + flag (half day):
      - Locale detection from $LANG / $LC_MESSAGES / $LC_ALL.
      - --lang flag override on root command.
      - Fallback chain: --lang → env → English.
      
      Phase 4 — Spanish translation pass (1-2 days):
      - Founder + friend-network review panel.
      - Side-by-side review tooling: dsd health --lang=es vs --lang=en.
      - Russian and Chinese added as pipeline matures, before public push.
      
      Phase 5 — Tests (half day):
      - Snapshot tests per locale for representative outputs.
      - Test that --json output stays English regardless of locale.
      - Test fallback to English on missing keys.
      
      Open decisions to make before starting:
      - Library choice (go-i18n vs golang.org/x/text vs roll-our-own)
      - String storage format (TOML vs JSON vs YAML — affects translator UX)
      - String ID convention (e.g. "network.gateway.unreachable")
      - Plural handling for Russian (3 forms) and Chinese (no plurals)
      - Where Sprintf interpolation arguments fit into translatable strings
      
      What stays English regardless of locale (machine + diagnostic contracts):
      - JSON / YAML output (programmatic consumers)
      - Debug logs (universal issue reports)
      - Source code, comments, commit messages, API responses

### Quality
- [ ] 🔴 **Systematic error-handling audit & refactor.** Pattern observed
      across multiple bugs found 2026-05-09 to 2026-05-10:
      
      DashDiag has a category of silent-failure bugs where errors are
      swallowed, missing data is interpreted as "everything fine", and
      the boundary between "no problem" / "no data" / "couldn't measure"
      is not surfaced. Examples found in this session:
      
      1. F0 drilldown silently skipped in non-TTY mode (renderer mode check)
      2. Systemd OK on non-systemd systems (empty insight list → OK)
      3. KernelSecurity OK on no-MAC systems (same pattern)
      4. SELinux insight orphaned by check name mismatch
      5. Network ICMP privilege failure → CRIT "gateway unreachable"
      6. Zram percentage field exists but never populated
      
      All 6 are instances of the same architectural pattern: empty results
      look like healthy results; skipped checks look like passing checks.
      
      Fix is systematic, not per-bug. Do post-launch but soon (1-2 weeks):
      
      Phase 1: Audit (1-2 days). Read every collector and analysis function.
        List every silent-failure path. Output: markdown doc.
      
      Phase 2: Define semantics (half day). Add explicit status field for
        "couldn't run" vs "ran and found nothing". Already partial via
        Systemd/KernelSecurity INFO change today; needs consistency.
      
      Phase 3: Refactor collectors (2-3 days). Each returns
        `{Data, Status: "ok"|"no_data"|"error", Reason: string}` instead
        of just `(Data, error)`.
      
      Phase 4: Refactor analysis (1-2 days). Heuristics check status field
        before computing thresholds. Status != "ok" → INFO insight explaining,
        not OK fallthrough.
      
      Phase 5: Test patterns for error paths (1-2 days). For each collector
        test: required file missing, command absent, EPERM, empty/malformed
        input, timeout. Verify result is informative.
      
      Total: ~1-2 weeks post-launch. Worth it: eliminates entire class of
      bugs, makes DashDiag self-diagnosing, improves trust ("OK" actually
      means OK).
- [ ] Golden file tests for all renderers (`go test ./internal/render/... -update`)
- [ ] **Privilege-aware UX messaging.** Pairs with systematic error-handling
      refactor above. Once collectors return explicit `{Status, Reason}`
      including degraded-due-to-privilege cases, the renderer should:
      
      1. Per-check inline message when degradation happens:
         "Network ℹ️  ICMP unavailable as non-root user — gateway not verified
                     For full check: sudo dsd health
                     Or: sudo setcap cap_net_raw=ep ~/bin/dsd"
      
      2. Optional bottom-of-output footer when ANY check degraded:
         "ℹ️  N checks ran with reduced accuracy due to user privileges.
              See per-check messages above. Run `dsd help privileges`."
      
      Considered and rejected: a generic always-on banner when running
      as non-root ("running as user, results may be inaccurate"). Would
      cause banner-blindness within days. The right pattern is
      check-specific messaging only when degradation actually happened,
      not a generic warning that fires regardless.
      
      Don't ship this until the systematic refactor lands — it depends
      on collectors being able to distinguish "I ran fine and found
      nothing" from "I couldn't run for privilege reasons" from "I
      ran with reduced data."
- [ ] Contract tests in `test/contract/` — validate JSON output against schema
- [ ] Coverage report: `make cover` — identify packages under 70%

### SDLC
- [ ] cosign key generation for release binary signing
- [ ] Homebrew formula (Formula/dsd.rb in a tap repo)
- [ ] Install script (install.dashdiag.sh — curl | sh)

### Testing (deferred)
- [ ] 🔴 **Non-root user testing matrix.** Critical gap discovered 2026-05-10:
      DashDiag's first non-root Linux test in project history happened
      today on the 2011 MacBook, and immediately surfaced a launch-blocking
      bug (Network privilege issue → false-positive CRIT). Five previous
      testing surfaces all masked the issue:
      
      1. Unit tests don't actually exec privileged operations
      2. CI tests run with whatever capabilities Actions grants
      3. Mac uses different ping/network stack — privilege issues don't
         translate
      4. Docker tests ran as root (default Docker user) — privileged
         ICMP works
      5. Docker tests on Alpine/Fedora same as above
      
      This means **other checks likely have similar non-root degraded
      behaviour** we haven't observed yet:
      
      Likely affected by privilege:
      - IO check: /proc/PID/io requires CAP_SYS_PTRACE or same-user
      - FDLimits check: /proc/PID/fd/ has user-restricted access
      - Processes drilldown: limited info for other users' processes
      - Network drilldown: ss -tnp shows process info only for own connections
      - Systemd drilldown: journalctl access varies by unit
      
      Likely safe (world-readable interfaces):
      - Memory, CPU, Swap, Disk, Clock, Sysctl, KernelSecurity
      
      Required testing matrix:
      
      Per distro × {root, normal user, CAP_NET_RAW set} × all 12 checks
      
      Currently 1×1 (only Ubuntu non-root via 2011 MacBook). Need:
      - Ubuntu 22.04 + 24.04 (most common server distro)
      - Fedora 40 (RPM family proxy)
      - Alpine 3.21 (musl/busybox edge cases)
      - Rocky 9 (RHEL-compatible enterprise)
      - All under all three privilege levels
      
      Implementation: Docker tests with `--user 1000:1000` flag + a
      separate test pass with `setcap cap_net_raw=ep` on the binary.
      
      Pair with the systematic error-handling refactor (NEXT/Quality):
      once collectors return explicit "I couldn't run because EPERM",
      tests verify "given user level X, check Y returns appropriate
      status" rather than just "check Y produces some output".
      
      Estimated: 2-3 days for the matrix expansion alone, after the
      systematic refactor lands.
- [ ] P2.8 Flatcar — requires registry authentication
- [x] ~~P5.1 Fedora 40~~ ✅ validated 2026-05-10 in docker
- [ ] P5.2 Oracle Linux 9, P5.3 AlmaLinux 9 — both binary-compatible
      with Rocky Linux 9 (already validated). Skip unless an enterprise
      prospect specifically requests one.
- [ ] RHEL 9 on Proxmox VM — 60-90 minutes of work via Red Hat Developer
      free subscription. Adds NO technical signal beyond Rocky Linux 9
      (already validated, binary-compatible). Marketing-only value:
      "tested on RHEL 9" reads better than "tested on Rocky Linux 9
      (RHEL-compatible)" to enterprise procurement processes.
      Defer until: an enterprise prospect specifically asks about RHEL
      OR you want a satisfying low-cognitive-load infrastructure task
      to break up strategic work.
- [x] ~~Alpine 3.21 verification~~ ✅ validated 2026-05-10 in docker
      All 12 collectors green, F0 Memory drilldown fires correctly with
      real process attribution (stress-ng-vm at 29.4%/575.7MB shown
      inline). Wall time 1.3s. busybox concerns turned out to be
      non-issues for the collectors that ran. Disk drilldown not
      exercised in container — would need filesystem fill test, but
      no evidence of issues from the basic suite.
      Minor UX nit (not launch-blocking): Systemd check returns OK on
      Alpine when systemd isn't present at all. Should arguably return
      "N/A" or "not applicable" rather than OK to avoid misleading users.
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
- [ ] `dsd compare` — multi-server side-by-side comparison (FEATURES.md F2)
- [ ] `dsd policy` — YAML policy file, CI gate (FEATURES.md F1, F3)

### Gate: 3+ users request configurable thresholds
- [ ] Configurable thresholds via config file (~/.dsd/config.yaml)
      Defer until 3+ users request it. Keep minimal scope:
      override specific thresholds, defaults applied otherwise.
      Connects to policy-as-code (FEATURES.md F1, F3) when built.
      See KEYORIX_FOUNDATION.md §6 — defaults, not configuration.

### Gate: AI ops integration becomes priority (~year 2)
- [ ] `dsd mcp` — MCP server subcommand for AI assistant integration
      DashDiag's --json output is already AI-ready. Wrap as MCP server
      so Claude/Cursor/etc. can call dsd_health(), dsd_diff() etc. directly.
      ~1 week of work. Don't market heavily — let it be discovered.
      See PRODUCT_IDEAS.md §0 — portfolio MCP layer.

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
- [ ] `--share` 90-day retention (paid tier feature, see docs/SHARE_DESIGN.md)

### Gate: 10+ paying teams
- [ ] UnpackOps RCA platform

### Gate: UnpackOps RCA validated
- [ ] Gauge (FinOps product)

### Strategic docs (see private gitignored files)
- KEYORIX_FOUNDATION.md — philosophy, audience, method
- POSITIONING.md — brand, voice, messaging
- STRATEGY.md — 5 monetization paths
- FEATURES.md — 11 enterprise features ranked by enterprise pull
- LAUNCH_PREP.md — README/GIF/HN post sequence
- PRODUCT_IDEAS.md — xwan, future products, acquisition lens

---

## BUGS / KNOWN ISSUES

### In progress
- [ ] macOS swap threshold producing false WARNs (sent to Claude Code 2026-05-08)
      Platform-aware thresholds: Linux 20%/50%, macOS 75%/90% gated by
      memory pressure (sysctl kern.memorystatus_vm_pressure_level)

### Known limitations (not bugs)
- CPU stress: FAIL on busy machines — mitigated by baseline skip + cores*2 spinners
- IO stress: no iostat in Colima Lima VM — graceful skip expected
- Flatcar: registry access denied — deferred
- macOS: clock OffsetMs always -1 (by design — no offset API without sudo)
- Any container: Systemd Available=false (by design)
- Memory WARN in 512MB containers — slab cache threshold fires (expected)

### Pre-existing
- [x] ✅ ~~`--qr` shows empty QR (shareURL stub)~~ RESOLVED 2026-05-10
      `output.PrintQRCode` was already returning silently when URL is empty
      (not actually rendering an empty QR). Real issue was UX — `--qr` and
      `--share` flags appearing in `--help` despite share backend not
      being implemented. Fix: marked both flags as hidden in cmd/root.go.
      Flags still functional (no breaking change) but invisible from help.
- [x] ✅ ~~`dsd health --weekly` needs 7 days of data~~ NOT A BUG. By design.
      Already shows clear message when state has fewer than 7 runs:
      "Not enough data yet. Run dsd health for 7+ days first." Tested
      working with accumulated state.
- [x] ✅ ~~`dsd services` empty state needs real config testing~~ RESOLVED.
      Empty state already prints helpful message with example yaml config.
      "Needs real config testing" was scope creep, not a bug. Defer real
      config integration testing to NEXT phase.
- [x] ✅ ~~SELinux denial insights use Check name "SELinux" but collector
      name is "KernelSecurity"~~ RESOLVED 2026-05-10. Fixed insight check
      name to "KernelSecurity" so renderer prefix matching can attach
      drill-down details. One-line change in heuristics.go line 404.
- [ ] Zram usage percentage not actually populated. Discovered while
      planning testing on a 2011 MacBook with zram-enabled Ubuntu.
      internal/collectors/swap.go counts zram devices via
      filepath.Glob("/sys/block/zram*") and sets ZramDevices, but
      never reads /sys/block/zram*/mm_stat or /sys/block/zram*/io_stat
      to populate ZramUsedPct (the field exists in models.SwapInfo
      but stays at 0). Low priority — affects systems using zram
      (uncommon but real, e.g. mobile-derived distros, memory-constrained
      servers). Fix: read mm_stat for compressed/decompressed sizes,
      compute compression ratio, surface as ZramCompressionRatio and
      populate ZramUsedPct from /proc/swaps zram device entries.

---

## BUGS FIXED

### Systemd and KernelSecurity now report INFO when not applicable (2026-05-10)

Previously: on systems without systemd (Alpine, OpenWrt, most Docker
containers, macOS) the Systemd check returned an empty insight slice,
which the renderer interpreted as OK. Same problem for KernelSecurity
on systems with no SELinux/AppArmor active. Users got "Systemd OK"
when systemd wasn't even running, which is misleading.

Fix in `internal/analysis/heuristics.go`:
- `checkSystemd` now returns INFO insight "systemd not present on this
  system" when `SystemdInfo.Available == false`
- `checkKernelSecurity` now returns INFO insight when neither SELinux
  nor AppArmor is actively enforcing. Treats `present + mode=disabled`
  the same as `not present` — common in containers where /sys reports
  the host's AppArmor state but no profiles apply.

Tests added: `TestSystemdNotAvailable`, `TestSELinuxDisabled`,
`TestKernelSecurityEnforcing`. Existing `TestSELinuxAbsent` updated.

Verified on Alpine 3.21 ARM64, Fedora 40 ARM64, and macOS arm64 — all
three correctly show INFO for these checks now.

### F0 drilldown — full check coverage verified (2026-05-10)

Verified all testable checks fire their drilldown in Docker (Fedora 40 ARM64).
Three bugs found and fixed in this session.

**Verification results:**

| Check          | Triggered | Drilldown fired | Content valid | Notes |
|----------------|-----------|-----------------|---------------|-------|
| CPU            | YES CRIT  | YES             | YES           | bash busyloops, 2 pinned CPUs, 122% load |
| Memory         | YES CRIT  | YES             | YES           | verified 2026-05-10 (overcommit threshold) |
| Processes (zombie) | YES WARN | YES           | YES           | verified 2026-05-10 |
| Processes (hung) | YES WARN | YES (FIXED)    | YES (FIXED)   | was routing to ZombiesWithParent — now HungProcesses() |
| IO             | YES WARN  | YES (FIXED)     | YES           | empty table bug fixed; verified with active DNF I/O |
| Disk           | YES CRIT  | YES (FIXED)     | YES (FIXED)   | root files now visible — fixed per-child du -sh |
| FDLimits       | YES WARN  | YES             | YES           | Python opens 1024/1024 FDs |
| Network        | YES WARN  | YES             | YES           | 160 CLOSE_WAIT via Python socket pairs |
| Sysctl         | YES CRIT  | YES             | YES           | sysctl -w net.core.somaxconn=128 |
| Swap           | NO        | N/A             | N/A           | deferred — no swap in Docker, needs VM |
| Systemd        | NO        | N/A             | N/A           | deferred — no real systemd in container |
| Clock          | NO        | N/A             | N/A           | deferred — needs NTP manipulation or broken sync |
| KernelSecurity | NO        | N/A             | N/A           | deferred — needs SELinux enforcing with denials |

**Bugs fixed:**

1. **Processes hung drilldown mismatch** (`drilldown/processes.go` + `drilldown/drilldown.go`):
   When Processes fired for "hung (uninterruptible)" the dispatch called
   `ZombiesWithParent`, returning a zombie table (empty, wrong title).
   Fix: added `HungProcesses()` that scans for state=="D"; dispatch routes
   messages containing "hung" or "uninterruptible" to it.

2. **IO drilldown empty table** (`drilldown/io.go`):
   When IO fired from a transient latency spike but the 500ms per-process
   sample captured no active I/O, the drilldown returned empty rows.
   Renderer printed only the title ("Top processes by I/O:") with no content.
   Fix: set `d.Note = "no active I/O detected in sampling window"` when rows==0,
   so the note renders instead of a dangling title.

3. **Disk drilldown misses large files at mount root** (`drilldown/disk.go`):
   `du --max-depth=1 /mount` lists subdirectories only; a large file at the
   root (e.g. 87MB fill file) was invisible — only `lost+found` at 12K showed.
   Fix: switched to `os.ReadDir(mount)` + per-child `du -sh <full-path>` which
   includes both files and directories in the listing.

**Deferred (not bugs, need VM-based testing):**
- Swap drilldown: no swap available in Docker containers typically.
  To test: bare metal / VM with swap configured, run stress-ng --vm.
- Systemd drilldown: requires real systemd; Docker containers use init.
  To test: Fedora/Ubuntu VM, systemctl stop <service>, run dsd.
- Clock drilldown: requires actual NTP drift.
  To test: VM with chrony/ntpd installed, disconnect from NTP source.
- KernelSecurity drilldown: requires SELinux in enforcing mode with denials.
  To test: Fedora/RHEL VM with selinux=enforcing and a policy violation.

**v0.2.0 proposal:** All testable drilldowns verified + 3 bugs fixed.
Deferred items are environment constraints (no systemd, no swap, no SELinux
in containers), not code bugs. Safe to tag v0.2.0 once release artifacts
(CHANGELOG, README) are ready.

---

### Fedora 40 ARM64 — basic compatibility confirmed (2026-05-10)

Tested in docker container `fedora:40` with `--privileged -v PWD:/dashdiag`.
Installed `procps-ng iproute systemd jq stress-ng` via dnf. All 12
collectors ran without crashes. Wall time ~1.3s. Output format clean.

This means RHEL 9 family (Rocky, Alma, RHEL itself) and Fedora 40+
should all work — same kernel family, same systemd version range,
same /proc layout. P5.1 Fedora can be marked validated.

Two issues surfaced during this test (now in NOW section):
- F0 drilldown not firing end-to-end (regression from today's ship)
- JSON output contaminated with progress logs

Neither is Fedora-specific — they appear on every Linux distro.
Fedora just happened to be the test bed where they were caught.

### F0 — Inline drill-down shipped (2026-05-09)

All 12 checks now produce inline attribution on WARN/CRIT. Healthy
systems unchanged — drilldown code never runs on OK checks.

**New files:**
- `internal/models/insight.go` — Details struct added to Insight
  (Type, Title, Columns, Rows, KV, Note)
- `internal/drilldown/drilldown.go` — PopulateAll dispatcher +
  shared helpers (walkProcs, runCmd, formatBytes, mount/unit parsers)
- `internal/drilldown/memory.go` — /proc/PID/status VmRSS on Linux,
  ps on macOS
- `internal/drilldown/cpu.go` — double-sample for accurate CPU%
- `internal/drilldown/swap.go` — /proc/PID/status VmSwap on Linux;
  nil+note on macOS (no public API)
- `internal/drilldown/disk.go` — du --max-depth=1 (macOS: -hd 1)
  with os.ReadDir fallback
- `internal/drilldown/io.go` — double-sample /proc/PID/io with 500ms
  gap on Linux; nil+note on macOS
- `internal/drilldown/network.go` — ss -tnp with /proc/net/tcp
  fallback on Linux, netstat on macOS
- `internal/drilldown/processes.go` — /proc/PID/stat zombie+parent
  lookup on Linux, ps on macOS
- `internal/drilldown/systemd.go` — journalctl -u <unit> tail
- `internal/drilldown/fdlimits.go` — /proc/PID/fd + /proc/PID/limits
  on Linux, lsof on macOS
- `internal/drilldown/clock.go` — chronyc tracking / timedatectl on
  Linux, sntp on macOS
- `internal/drilldown/sysctl.go` — /proc/sys/ reads with
  recommended-value table
- `internal/drilldown/kernelsec.go` — aa-status + getsebool on Linux

**Modified files:**
- `cmd/health.go` — wires drilldown.PopulateAll(ctx, insights,
  results) after ApplyThresholds; adds --terse flag (skips drilldown)
- `render/health.go` — renderDetails() prints tabular rows or KV
  pairs indented under the check line (ModeHuman only)
- `render/json.go` — JSONInsight.Details *models.Details propagated
  from insight (backward-compatible: field is omitempty)

**Behaviour summary:**
- Healthy: no drilldown, wall time unchanged (~1.3s)
- WARN/CRIT: attribution inline, <2s typical
- `--terse`: skips drilldown even on WARN/CRIT (minimal output)
- `--json`: always includes Details when present

**Next step:** Test on a real system with actual WARN/CRIT firing to
verify output format, indentation, and table rendering look right
before tagging v0.2.0.

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
- [x] MACPolicy collector renamed to KernelSecurity
      MAC abbreviation collided with macOS naming — confused users on Mac

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
- `dsd how "check if a port is open"` — built-in command lookup mode.
   The strategic insight: generic cheat sheets (like the giant Linux
   command mouse pads engineers buy) are useless during incidents. They
   contain commands you'd already know if you used them daily, and lack
   commands you'd need precisely when something unfamiliar is broken.
   They serve as PLACEBO COMPETENCE — make engineers feel less anxious
   without solving the underlying problem.
   
   DashDiag is uniquely positioned to do better because it knows what's
   wrong AND knows what commands are available on this specific system.
   No cheat sheet can do this. No Stack Overflow answer can. Even AI
   assistants don't know your specific system without DashDiag's data.
   
   Example interactions:
     dsd how "check firewall rules"
     → Detects nftables vs iptables vs ufw via systemctl + which
     → Suggests the right command for THIS system
     → Cross-references to dsd net for automatic diagnosis
   
     dsd how "find process holding a port"
     → Suggests ss -tnlp on Linux with iproute2
     → Falls back to lsof -i if iproute2 not present
     → Falls back to netstat -tnlp on RHEL 6 / minimal containers
   
   Replaces cheat sheets entirely. Reinforces "burn the cheat sheet"
   positioning. High strategic value, medium build cost (~2-3 weeks
   for v1 with ~50 common queries).
- Conntrack table saturation check — read /proc/sys/net/netfilter/nf_conntrack_count
   vs nf_conntrack_max. When the table fills, new connections silently fail.
   Common cause of "the network feels slow but I can't tell why" on systems
   with iptables/nftables. Belongs in the Network check, deferred until
   F0 attribution work is done.
- DNS resolver attribution — slow or failing DNS lookups attributed to
   specific upstream nameservers. Often the actual cause of "the app is slow"
   is one upstream resolver being slow. Read /etc/resolv.conf, time queries
   to each, attribute slowness. Belongs in the Network check.
- Per-connection TCP diagnostics — parse `ss -tno state established` for
   timer info, retransmit counts, send/recv queue depths. Detects:
   high retransmit count = packet loss to specific peer (network problem,
   not app); send queue persistently > 0 = receiver overwhelmed (downstream
   congested); recv queue persistently > 0 = local app reading too slowly
   (consumer bug). Per-connection attribution, very actionable.
- Upstream connectivity check (opt-in via `--check-upstream` flag) — TCP
   connect to 8.8.8.8:53 and 1.1.1.1:53, measure handshake time. Both slow
   = real internet problem; one slow other fast = specific path issue.
   Opt-in because external probing changes DashDiag's character (it's no
   longer purely local diagnostic). Sysadmins should consciously decide.
- Pre/post-deploy diff (FEATURES.md F1) — capture baseline, diff after deploy
- Multi-env compare (FEATURES.md F2) — diff prod vs staging system state
- GitHub Action for PR checks (FEATURES.md F3) — block merges on CRIT
- Drift detection (FEATURES.md F4) — daily snapshots, trend analysis
- Approval workflow (FEATURES.md F5) — Slack-mediated risky-change approval

---

## DECISIONS LOG

2026-05  Rejected: AI flag in collectors — deterministic by design
2026-05  Rejected: Persistent TUI dashboard — btop/lazydocker/k9s exist
2026-05  Rejected: RPG achievements — too gamey for DevOps/SRE audience
2026-05  Rejected: Speed tier differentiation — runs locally, no server queues
2026-05  Deferred: Watermarks on --share — engineers would remove them
2026-05  Renamed: MACPolicy → KernelSecurity (macOS naming collision)
2026-05  Decided: Defaults over configuration — see KEYORIX_FOUNDATION.md §6

---

## HOW TO USE THIS FILE

When you complete a NOW item: mark [x], pull from NEXT if NOW empties, commit.
When you find a bug: add to BUGS, escalate to top of NOW if blocking.
When someone requests a feature: add to IDEAS first, promote only after planning.
When a phase gate opens: move from LATER to NEXT (never directly to NOW).
Weekly review: 5 minutes — NOW accurate? anything stuck? Ideas to promote?

---

## Customer journey & inline drill-down (reference for NOW item #1)

### The problem

DashDiag currently tells the user **what's wrong** and gives a hint
about **what command to run next**. The user must:

1. Read the hint
2. Copy the command
3. Run it manually
4. Interpret the output themselves
5. Repeat for each issue

That's better than nothing but still passes cognitive load to the user.
The Keyorix philosophy says: if DashDiag knows the command to run,
DashDiag should run it and show the result.

### The four-step customer journey

The strongest version of DashDiag closes the loop:

1. **Detect** — what's wrong (current capability)
2. **Explain** — show the data that proves it (Feature 1, this item)
3. **Contextualize** — show how it changed over time (Feature 2 = F4 drift, deferred)
4. **Hypothesize** — suggest root causes (separate product, UnpackOps RCA)

Right now we're at step 1.5. Step 2 is the highest-value next move
because it absorbs the most cognitive load for the lowest engineering
cost.

### What inline drill-down looks like

```
Memory       ❌  RAM at 94% (1.2 GB free of 16 GB)
   Top processes by memory:
   PID    MEM%  RSS    COMMAND
   12345  31.4  5.0GB  /opt/postgres/bin/postgres
   23456  18.2  2.9GB  /opt/elasticsearch/bin/java
   ... (5 more)

CPU          ⚠️  CPU usage at 87% sustained for 3 minutes
   Top processes by CPU:
   PID    CPU%  COMMAND
   12345  45.2  /opt/postgres/bin/postgres -D /var/lib/postgres
   23456  18.7  python3 /opt/etl/process_orders.py
   ... (5 more)
```

User sees the cause inline. No copy-paste cycle. No "let me Google
this command" detour. Information arrives where attention already is.

### Per-check drill-down spec

Each check that fires WARN or CRIT auto-collects relevant context.
The principle is **attribution relative to the limit being hit**, not
just absolute values. Showing "process X is at 980/1000 FDs" is more
useful than "process X has 8000 FDs."

| Check          | Auto-collect on WARN/CRIT |
|----------------|---------------------------|
| CPU            | Top 10 processes by CPU%, plus user vs kernel CPU breakdown |
| Memory         | Top 10 processes by RSS |
| Swap           | Top 10 processes by VmSwap (from /proc/PID/status on Linux) |
| Disk           | Top 5 largest directories on the affected mount, plus recently-grown files (mtime within 24h) |
| IO             | Top 5 processes by combined read+write bytes/sec (from /proc/PID/io on Linux) |
| Network        | TCP states by process: TIME_WAIT pileup (port exhaustion risk), CLOSE_WAIT leak (app bug), stuck SYN_SENT/SYN_RECV. Plus failed DNS lookups. Plus gateway ping latency/jitter (20 samples, ~4s, avg/stddev/loss). |
| Processes      | Zombie processes with their PARENT process info (parent is the actual offender) |
| Systemd        | Last 20 lines of journalctl for failed units |
| FDLimits       | Top 10 processes by FD usage as % of their individual limit |
| Clock          | Output of chronyc tracking or platform equivalent |
| Sysctl         | Current value vs recommended for failing settings |
| KernelSecurity | Which AppArmor profiles in complain mode, which SELinux booleans off |

**Platform notes:**
- Linux: full attribution available via /proc filesystem
- macOS: per-process swap attribution not available (no public API), fall back to top-by-RSS
- macOS: FD attribution via lsof, slower than Linux's /proc but works
- macOS: I/O attribution via fs_usage or limited; show platform note if not available
- Non-root users: show what's accessible, note that some processes may be hidden

**What attribution does NOT solve:**
Attribution shows WHICH process. It doesn't explain WHY the process is
doing what it's doing. That's UnpackOps RCA territory (separate product).
Stay in attribution lane for DashDiag.

Example: "postgres is using 5GB of swap" is attribution (good for DashDiag).
"Postgres is using 5GB of swap because shared_buffers is misconfigured" is
causation (UnpackOps RCA territory, not DashDiag).

### Suggested data structure

Each check exposes a `Details` field in its JSON output. CLI renderer
shows it inline. JSON consumers get structured data. Hints stay as
fallback for users who want to dig deeper.

```json
{
  "name": "Memory",
  "status": "CRIT",
  "message": "RAM at 94% (1.2 GB free of 16 GB)",
  "details": {
    "type": "process_table",
    "title": "Top processes by memory",
    "columns": ["PID", "MEM%", "RSS", "COMMAND"],
    "rows": [
      ["12345", "31.4", "5.0GB", "postgres"],
      ["23456", "18.2", "2.9GB", "java"]
    ]
  },
  "hints": [
    "ps aux --sort=-%mem | head -10",
    "vmstat 1 5"
  ]
}
```

### Implementation notes

- Drill-down only runs when status is WARN or CRIT (don't slow down OK case)
- `--terse` flag for users who want only the verdict (preserves current behavior)
- JSON output always includes details (machine consumers can choose to ignore)
- Each collector implements its own drill-down — no central drill-down engine
- Keep drill-down output capped (top 10, not top 100) to avoid wall of text
- macOS and Linux use platform-appropriate commands internally

### Why this matters for launch

The current launch GIF would show: check fires → hint command → end.
With drill-down: check fires → cause appears inline → user understands.

That's a dramatically stronger first impression for HN. The "wow" moment
moves from "neat, it tells me what to run next" to "wait, it just told
me which process is the problem."

This is the feature that distinguishes "another diagnostic tool" from
"the tool engineers actually use."

### Why we're NOT building features 3 and 4 right now

**Feature 2 (drift detection)** is already in FEATURES.md as F4. Defer
until post-launch — requires persistent storage, comparison logic, and
benefits from real user feedback first.

**Feature 3 (causal explanation)** is UnpackOps RCA territory. Building
it into DashDiag would betray the Keyorix philosophy — DashDiag's
essential thing is "diagnose what's wrong with this server right now."
Cross-signal inference is a different essential thing and deserves its
own product.

---

## Network connection state diagnostics (reference for F0 Network check)

The Network check in F0 covers more than just "is the network up." It
diagnoses the four most common pathological TCP connection patterns,
each of which has a distinct cause and resolution.

### TIME_WAIT pileup

**What it means:** TCP closes a connection by holding the originating
socket in TIME_WAIT for ~60 seconds (2MSL timeout). This prevents stray
packets from a previous connection being misinterpreted by a new
connection on the same port pair.

**The failure mode:** Heavy short-lived connection load (web servers
without keep-alive, aggressive HTTP clients) accumulates TIME_WAIT
sockets by the thousands. The system runs out of source ports
(default range ~28K). New outbound connections start failing with
EADDRINUSE.

**Detection:** Count sockets in TIME_WAIT state, attribute to local
process/port via `ss -tnp state time-wait`.

**Thresholds:**
- WARN at 10,000 total TIME_WAIT
- CRIT at 30,000 (port exhaustion likely imminent)

**Common causes:**
- HTTP client without connection pooling
- Reverse proxy without upstream keep-alive
- Database client without persistent connections

### CLOSE_WAIT leak

**What it means:** Remote end closed the connection (sent FIN). Local
socket sits in CLOSE_WAIT waiting for the local application to call
`close()`. If the application has a bug and never closes the socket,
it stays in CLOSE_WAIT forever.

**The failure mode:** Application bug — missing `defer conn.Close()`,
missing `try/finally`, connection pool not releasing. Eventually
exhausts file descriptors.

**Detection:** Count sockets in CLOSE_WAIT state per-process via
`ss -tnp state close-wait`.

**Thresholds:**
- WARN at 200 CLOSE_WAIT for any single process
- CRIT at 1000 (almost certainly a bug, FD exhaustion approaching)

**Diagnostic value:** This is one of the most useful detections because
CLOSE_WAIT pileup is almost always a real bug, not a config issue. The
process attribution tells the user exactly which application to fix.

### Stuck SYN_SENT / SYN_RECV

**What they mean:**
- SYN_SENT: We sent SYN, never got SYN+ACK back. Typically a firewall
  silently dropping packets, or destination is down.
- SYN_RECV: We received SYN, sent SYN+ACK, never got the final ACK.
  Typically a SYN flood attack or misconfigured client.

**The failure mode:**
- High SYN_SENT to specific destinations = network connectivity problem
  (firewall, routing, destination down)
- High SYN_RECV without corresponding ESTABLISHED = either DDoS or
  client-side problem

**Detection:** Count sockets by state via
`ss -tnp state syn-sent` and `ss -tnp state syn-recv`.

**Thresholds:**
- WARN on SYN_SENT > 100 sustained
- WARN on SYN_RECV > 1000 (possible attack or load issue)

### What we're NOT trying to detect (yet)

- **Stale ESTABLISHED connections** (zero bytes for hours) — harder to
  detect cheaply, less actionable. Defer to v2.
- **Per-destination breakdown** — useful for security audits but
  belongs in `dsd security`, not health check.
- **Bandwidth per process** — requires nethogs or similar, often not
  installed, expensive to compute.
- **UDP error rates** — possible but less critical than TCP issues.
  Defer.

### What this gives users

```
Network      ⚠️  unusual connection patterns
   TIME_WAIT:    14,832 (high — port exhaustion possible)
   CLOSE_WAIT:   847 (likely application bug)

   Top processes with CLOSE_WAIT (likely socket leak):
   PROC                     CLOSE_WAIT  CMD
   python3[8423]            612         /opt/etl/scrape_orders.py
   nginx[7891]              198         /usr/sbin/nginx (worker)

   Top processes with TIME_WAIT:
   PROC                     TIME_WAIT   CMD
   nginx[7891]              12,400      /usr/sbin/nginx
   redis-cli[multiple]      1,800       short-lived connections

   → ss -tnp state close-wait
   → ss -s
```

That answers four questions in one screen:
1. Is something weird happening? Yes.
2. Which patterns? CLOSE_WAIT and TIME_WAIT both elevated.
3. Which process? python3 ETL job leaking sockets, nginx with TIME_WAIT pile-up.
4. What do I look at? Either fix the ETL bug, or tune nginx keep-alive.

That's actionable diagnosis. That's what distinguishes "another diagnostic
tool" from "the tool engineers actually use."

### Architectural note: active probing vs passive reading

DashDiag is starting to do **active probing** (sending packets, measuring
responses) in addition to **passive reading** (parsing kernel state).
These have different tradeoffs and should be visually distinguished in
output.

**Passive reading** (current approach for most checks):
- Cheap, fast, no external impact
- No permission issues, deterministic
- Just reads what the kernel already knows
- Wall time per check: 10-200ms

**Active probing** (gateway ping, TCP-connect, DNS query):
- Costs wall time (4s for 20 ping samples)
- May require capabilities (cap_net_raw for ICMP)
- Changes external state slightly (creates packets)
- Results vary with external conditions
- Wall time per probe: 1-10 seconds

**Wall time matters for UX:**

Current `dsd health` runs in ~1.3s — fast enough that engineers don't
break flow when running it during incidents. Adding a 4s gateway ping
to every run would triple wall time. That's a meaningful UX cost.

**Keyorix design rule for probing — tiered execution:**

> Match wall time to user intent. Healthy = fast. Broken = thorough.

```
Default `dsd health` — passive checks only, ~1.3s
├── If everything OK → done (no wall time penalty for healthy systems)
├── If WARN/CRIT detected → run inline drill-down
│   ├── Process attribution (cheap, <100ms)
│   ├── Connection state analysis (cheap, <200ms)
│   └── Active probes only for the failing check
│       └── Network failed → gateway ping (4s)
│       └── Disk failed → recently-grown files scan
│       └── (Each check decides its own probing budget)
```

User mental model this matches: "if it's healthy I want to know fast;
if it's broken I want to understand why."

**Future flags (not v0):**
- `--quick` — force passive-only mode even on WARN/CRIT
   (incident response: skip probes when you already know the problem)
- `--deep` — run ALL probing including upstream connectivity, bandwidth
   (periodic baseline runs, not incident response)

For F0:
- Gateway ping latency/jitter: only runs on Network WARN/CRIT,
   not on every health check (preserves the ~1.3s healthy-case wall time)
- Upstream connectivity probe: opt-in only via future `--check-upstream`
- Be opinionated about what to probe but make it visible — show user
   what was measured and why

### Parallel execution architecture (for F0 implementation)

Wall time matters for UX. Goroutines shrink wall time when you have
independent operations that block on I/O. Both apply to DashDiag.

**Three-phase execution model for F0:**

```
Phase 1: Parallel passive collection (verify already working)
   ├── 12 goroutines, one per check
   ├── errgroup with context timeout (5s max per check)
   └── Wait for all to complete or timeout
   Wall time: ~200-300ms

Phase 2: Conditional drill-down (new for F0)
   ├── For each check that returned WARN/CRIT:
   │   ├── Spawn drill-down goroutine for that check
   │   └── Drill-down internally parallelizes its work
   │       (e.g., Memory drill-down: worker pool of 8 reads 500 /proc/PID/status)
   └── Drill-downs run in parallel with each other
   Wall time when triggered: ~500ms-1s

Phase 3: Conditional probing (new for F0)
   ├── If Network drill-down needs gateway ping → ping (~1s)
   ├── Other probes parallel to ping if any
   └── Use errgroup.SetLimit() to cap concurrent probes
   Wall time when triggered: ~1s
```

**Resulting wall times:**
- Healthy system: ~300ms (Phase 1 only)
- WARN/CRIT system: ~1.5-2s (Phase 1 + 2 + 3)

Healthy systems actually get faster than the current 1.3s. Broken
systems take ~2s but provide actionable diagnosis instead of just
verdict.

**Key Go patterns to use:**

```go
import "golang.org/x/sync/errgroup"

// Worker pool with concurrency limit
g, ctx := errgroup.WithContext(ctx)
g.SetLimit(8) // 8 concurrent workers

for _, pid := range pids {
    pid := pid // capture loop variable
    g.Go(func() error {
        return readProcStatus(ctx, pid)
    })
}
if err := g.Wait(); err != nil { /* handle */ }

// Context with timeout per check
ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
defer cancel()
```

**Implementation rules:**

1. **Verify Phase 1 is already parallel.** Quick check:
   `grep -r "go func\|sync.WaitGroup\|errgroup" internal/`
   If sequential, this is a quick win — move to parallel goroutines first.

2. **Use worker pool for /proc iteration.** Don't spawn 500 goroutines
   reading /proc/PID/*. Use errgroup.SetLimit(8) or runtime.NumCPU().
   Prevents pathological behavior on systems with thousands of processes.

3. **Always use context.WithTimeout.** 5 seconds max per check. If
   something hangs (D-Bus to systemd can stall, ping can take longer
   than expected), it gets killed and reported as "Check X timed out"
   instead of blocking the whole run.

4. **Always use recover() in each goroutine.** A panic in one check
   should not crash DashDiag. Report "Check X errored: <reason>" instead.

5. **Test output stability.** Parallel execution must not produce
   non-deterministic output ordering. Collect results into a map keyed
   by check name, render in stable sorted order.

6. **Don't over-parallelize ping.** ping -c 20 -i 0.2 takes 4s by design
   (measuring jitter). Running parallel pings would skew the measurement.
   If 4s is too long, reduce sample count (-c 10 -i 0.1 = 1s, less data
   but still useful).

7. **Context-aware hints (small F0 enhancement).** Currently hints are
   static suggestions like "ss -tnp state close-wait". But ss may not
   be installed on RHEL 6, Alpine, or stripped containers.
   
   Each hint generator should check what's actually available on this
   system via exec.LookPath() and suggest the command that exists:
   
     if hasSS := exec.LookPath("ss"); hasSS == nil {
         hints = append(hints, "ss -tnp state close-wait")
     } else if hasNetstat := exec.LookPath("netstat"); hasNetstat == nil {
         hints = append(hints, "netstat -tnp | grep CLOSE_WAIT")
     } else {
         hints = append(hints, "(install net-tools or iproute2 to investigate)")
     }
   
   Small but meaningful: difference between "here's a command" and
   "here's a command that will actually work on YOUR system."
   ~1 day of work added to F0. The deeper version (`dsd how`) is in IDEAS.

---

## Strategy backup setup (NOW item — ~5 minutes)

8 strategic documents currently exist only on one laptop:
- KEYORIX_FOUNDATION.md (philosophy, ~970 lines)
- POSITIONING.md (brand, voice, category)
- STRATEGY.md (5 monetization paths)
- FEATURES.md (12 features incl. F0)
- LAUNCH_PREP.md (launch sequence)
- PRODUCT_IDEAS.md (xwan + portfolio)
- CONTENT_LINKEDIN_CHEATSHEET.md (launch content)
- CONTENT_HN_REDDIT_CHEATSHEET.md (launch content)

Plus BACKLOG.md (this file) which IS in the public repo.

Total ~3000 lines of strategic work. A laptop loss = catastrophic.

### 5-minute setup commands

```bash
# Create a fresh local directory for the strategy repo
cd ~
mkdir -p dev/keyorix-strategy
cd dev/keyorix-strategy
git init

# Copy current strategy docs from dashdiag/
cp /Users/andreibeshkov/dev/dashdiag/KEYORIX_FOUNDATION.md .
cp /Users/andreibeshkov/dev/dashdiag/POSITIONING.md .
cp /Users/andreibeshkov/dev/dashdiag/STRATEGY.md .
cp /Users/andreibeshkov/dev/dashdiag/FEATURES.md .
cp /Users/andreibeshkov/dev/dashdiag/LAUNCH_PREP.md .
cp /Users/andreibeshkov/dev/dashdiag/PRODUCT_IDEAS.md .
cp /Users/andreibeshkov/dev/dashdiag/CONTENT_*.md .

# Add a README explaining what this repo is
cat > README.md <<'EOF'
# Keyorix Strategy

Private strategy and positioning documents for Keyorix S.L.

This repo is the canonical source of truth for company-level strategic
thinking. The public dashdiag/keyorixhq repos contain operational
documentation only.

## Documents

- KEYORIX_FOUNDATION.md — philosophy and conviction (the why)
- POSITIONING.md — brand, voice, audience, category framing
- STRATEGY.md — monetization paths
- FEATURES.md — feature roadmap with priority
- LAUNCH_PREP.md — launch sequence
- PRODUCT_IDEAS.md — future products beyond DashDiag and Keyorix Vault
- CONTENT_*.md — drafts for launch coordination

## Access

Restricted to founders and approved cofounders post-ENISA verification.
EOF

git add -A
git commit -m "Initial strategy snapshot - 2026-05-09"

# Create the private repo on GitHub and push
gh repo create keyorixhq/strategy --private --source=. --push

# Verify it pushed
gh repo view keyorixhq/strategy --web
```

### Sync script for ongoing updates

After initial setup, save this as `~/bin/sync-keyorix-strategy.sh`:

```bash
#!/bin/bash
set -e

DASHDIAG=/Users/andreibeshkov/dev/dashdiag
STRATEGY=$HOME/dev/keyorix-strategy

# Copy current versions
cp "$DASHDIAG"/KEYORIX_FOUNDATION.md "$STRATEGY"/
cp "$DASHDIAG"/POSITIONING.md "$STRATEGY"/
cp "$DASHDIAG"/STRATEGY.md "$STRATEGY"/
cp "$DASHDIAG"/FEATURES.md "$STRATEGY"/
cp "$DASHDIAG"/LAUNCH_PREP.md "$STRATEGY"/
cp "$DASHDIAG"/PRODUCT_IDEAS.md "$STRATEGY"/
cp "$DASHDIAG"/CONTENT_*.md "$STRATEGY"/ 2>/dev/null || true

cd "$STRATEGY"
git add -A

# Only commit if there are changes
if ! git diff --cached --quiet; then
    git commit -m "snapshot $(date +%Y-%m-%d-%H%M)"
    git push
    echo "Strategy backed up to private repo"
else
    echo "No changes to back up"
fi
```

Make it executable: `chmod +x ~/bin/sync-keyorix-strategy.sh`

Run after every strategy session.

### When ENISA cofounder checks clear

Grant cofounders access to the strategy repo:
```bash
gh api repos/keyorixhq/strategy/collaborators/USERNAME -X PUT \
  -f permission=push
```

Or via web UI: github.com/keyorixhq/strategy/settings/access

### Defense in depth (after launch)

Once the immediate backup is in place, consider additional layers:
- Local encrypted backup to external drive (monthly)
- iCloud Drive copy of the strategy repo (auto-syncs continuously)
- Optional: GitLab.com mirror for EU sovereignty story consistency
   (GitHub is owned by Microsoft, US jurisdiction)

Don't let perfect-backup planning prevent imperfect-backup execution.
GitHub private repo tonight is enough.
