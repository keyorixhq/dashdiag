# DashDiag Unified Flag Design

## Current state (audited against code)

Global flags registered in root.go (inherited by all commands):
  json, plain, compact, debug, diff, out, post-mortem, qr, report,
  share, since-deploy, story, watch, weekly, yaml

Most of these are aspirational stubs — registered everywhere,
only health actually implements them. The ones that actually work
broadly: json (partially), plain (partially).

Per-command flags that exist today:
  disk:      deep
  docker:    deep
  gpu:       deep
  kvm:       deep
  net:       deep
  pve:       deep
  health:    deep, tls, gpu, firmware, packages, terse, report,
             watch-interval, policy
  security:  drift, save-baseline, suid
  logs:      since (duration string, e.g. "1h", "24h")
  timeline:  hours (integer — INCONSISTENT with logs)
  tls:       endpoint, endpoints-file, warn-days, crit-days, all, json
  cve:       all, json, oval, oval-scan
  cis:       level, stig, plain, fail-only, json
  cpu:       plain (local duplicate of global)
  compare:   plain, all
  story:     plain

---

## Problems identified

1. --json broken in 6 commands (fix-json-flag-prompt.md covers this)

2. --since vs --hours: logs uses "1h"/"24h" string, timeline uses integer.
   Inconsistent. One standard needed.

3. --plain registered globally AND locally on some commands (cpu, cis, compare,
   story). Local declarations shadow the global unnecessarily.

4. --deep missing on: k8s, security, thermal, processes, services.
   Some have natural deep modes (k8s OS-layer, security SUID scan).
   Others have nothing more to show (thermal is already all it has).

5. --watch registered globally but only health reads it.
   Genuinely useful on thermal and processes (live view). Noise everywhere else.

6. --out registered globally, nobody reads it anywhere. Pure stub.

7. --yaml registered globally, only health reads it. Low value for others.

---

## Proposed target state

### Tier 1 — Every diagnostic command must have these

--json      Output machine-readable JSON. Already in root.go. Fix 6 broken ones.
            After fix-json-flag-prompt.md: all commands have working --json.

--plain     Plain text, no colour, no emoji. Already in root.go.
            ACTION: remove local --plain declarations from cpu, cis, compare, story.
            All commands should just read the global flag instead.

These two are the only flags every command needs unconditionally.
Everything below is conditional on whether it makes sense for that command.

---

### Tier 2 — Time window: standardise on --since

Commands that look back in time should all use --since with a duration string.

Standard:   --since 1h   (default)
            --since 24h
            --since 7d
            --since 30d

TODAY:
  logs:     --since "1h"   ✅ already correct
  timeline: --hours 1      ❌ rename to --since, parse as duration

SHOULD ADD --since:
  cve:      currently no time window — but CVE data is static (package versions),
            so --since makes no sense here. SKIP.
  security: --drift compares against a baseline timestamp, not a window.
            --since doesn't map cleanly. SKIP.

VERDICT: Only timeline needs fixing (--hours → --since). No other commands
need a time window that don't already have one.

---

### Tier 3 — Deep mode: --deep

Add only where there is genuinely more data to collect.

TODAY:  disk, docker, gpu, kvm, net, pve, health ✅
SKIP:   thermal — already shows everything it can
SKIP:   processes — already shows everything it can
SKIP:   cron — already shows everything it can
SKIP:   hardware — no meaningful "deep" pass exists
SKIP:   tls — --endpoint already extends it, no deep concept needed

SHOULD ADD:
  k8s:       --deep already used internally (Deep bool on collector).
             The flag just isn't wired in cmd/k8s.go. ADD IT.
  security:  --suid is the "slow extra check" pattern — but --deep is cleaner
             than --suid as a user-facing flag. RENAME --suid → consolidate
             into --deep (--deep implies SUID scan + any future slow checks).
             KEEP --drift and --save-baseline as separate modes (they're not
             "more detail", they're different operational modes).
  services:  --deep already exists on the subcommand pattern (services deep).
             No flag needed — subcommand is the right model here.

---

### Tier 4 — Watch mode: --watch

Add only where live refresh actually helps the operator.

TODAY:  health ✅ (full implementation with --watch-interval)
ADD:    thermal — live temperature monitor is a real use case
ADD:    processes — live process view (like a lightweight top) is a real use case
SKIP:   everything else — --watch on `dsd disk` or `dsd k8s` would be slow,
        confusing, and not what operators reach for

Implementation for thermal and processes: simple loop, clear screen,
re-run collector every N seconds. Default 5s interval for these
(faster than health's 60s — they're lightweight collectors).
Use --watch-interval to override.

---

### Tier 5 — Output file: --out

Currently registered globally, nobody reads it.
DECISION: keep it global, implement it in the global PersistentPreRun
in root.go so it works for ALL commands at once without touching each file.
Redirect os.Stdout to the file before the command runs.

This is a 1-place fix for universal coverage. Low priority but clean to implement.

---

### Tier 6 — Flags to clean up / retire

--compact:      global, nobody reads it. Retire or implement.
--debug:        global, nobody reads it consistently. Retire.
--diff:         global, nobody reads it. Retire.
--post-mortem:  global, nobody reads it. Retire.
--qr:           global, nobody reads it. Retire.
--share:        global, nobody reads it. Retire.
--since-deploy: only health reads it. Keep on health, retire global.
--story:        only story cmd reads it. Not a general flag. Retire global.
--watch:        keep global (health + thermal + processes will read it).
--weekly:       global, nobody reads it. Retire.
--yaml:         only health reads it. Keep on health, retire global.

The global flag namespace is polluted with stubs that create user confusion
("why does dsd disk --watch do nothing?"). Clean them out.

---

## Target flag matrix

Command     | --json | --plain | --deep | --since | --watch | --out
------------|--------|---------|--------|---------|---------|------
health      |  ✅    |   ✅    |   ✅   |    -    |   ✅    |   ✅
cpu         |  ✅    |   ✅    |    -   |    -    |    -    |   ✅
gpu         |  ✅    |   ✅    |   ✅   |    -    |    -    |   ✅
thermal     |  ✅    |   ✅    |    -   |    -    |  ADD    |   ✅
processes   |  ✅    |   ✅    |    -   |    -    |  ADD    |   ✅
disk        |  FIX   |   ✅    |   ✅   |    -    |    -    |   ✅
docker      |  FIX   |   ✅    |   ✅   |    -    |    -    |   ✅
k8s         |  FIX   |   ✅    |  ADD   |    -    |    -    |   ✅
security    |  FIX   |   ✅    |  ADD   |    -    |    -    |   ✅
net         |  ✅    |   ✅    |   ✅   |    -    |    -    |   ✅
services    |  ✅    |   ✅    |    -   |    -    |    -    |   ✅
logs        |  ✅    |   ✅    |    -   |   ✅    |    -    |   ✅
timeline    |  ✅    |   ✅    |    -   | RENAME  |    -    |   ✅
cron        |  ✅    |   ✅    |    -   |    -    |    -    |   ✅
proc        |  ✅    |   ✅    |    -   |    -    |    -    |   ✅
kvm         |  ✅    |   ✅    |   ✅   |    -    |    -    |   ✅
pve         |  ✅    |   ✅    |   ✅   |    -    |    -    |   ✅
hardware    |  ✅    |   ✅    |    -   |    -    |    -    |   ✅
cis         |  ✅    |   ✅    |    -   |    -    |    -    |   ✅
cve         |  ✅    |   ✅    |    -   |    -    |    -    |   ✅
tls         |  ✅    |   ✅    |    -   |    -    |    -    |   ✅

FIX = already tracked in fix-json-flag-prompt.md
ADD = new work needed
RENAME = --hours → --since on timeline

---

## Change summary (what actually needs building)

Priority 1 — already have a prompt:
  fix-json-flag-prompt.md covers --json in 6 broken commands.

Priority 2 — small, high-value:
  A. timeline: rename --hours to --since (accept duration string like logs)
     1 flag rename + update parseSinceDuration usage in cmd/timeline.go
     Breaking change: --hours still accepted with deprecation notice.

  B. k8s: add --deep flag to cmd/k8s.go
     The collector already has Deep bool. Just wire the flag.
     1 line in init(), 1 line in runK8s().

  C. security: rename --suid to --deep
     --suid is cryptic. --deep is the convention. --suid stays as alias.
     1 flag rename in cmd/security.go + update help text.

Priority 3 — medium effort:
  D. --watch on thermal and processes
     Simple: loop + clear screen + re-run collector.
     Default 5s interval. Share --watch-interval from root.go.

  E. --out via root.go PersistentPreRun
     Redirect stdout once, works for all commands.

Priority 4 — cleanup:
  F. Remove dead global flags from root.go:
     compact, debug, diff, post-mortem, qr, share, weekly
     Move since-deploy, story, yaml, report to health-local flags.
     This is a minor breaking change (--weekly silently accepted → rejected).
     Do this in a separate commit with a clear note in CHANGELOG.

---

## What NOT to add

--format json|yaml|plain as a single flag instead of separate --json/--plain:
  This is cleaner design in theory but a breaking change on a tool that
  already has users. Not worth the churn.

--quiet / --silent:
  --plain already serves this. One less flag.

--no-color:
  Covered by --plain. Not needed separately.

--timeout:
  Each collector has its own timeout. A global override creates more problems
  than it solves. Skip.

--config:
  --policy on health covers this for the one command that needs it. Skip globally.
