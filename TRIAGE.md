# Work Queue — Open items by subsystem

Forward-looking index. BUGS.md stays the per-platform discovery log; this file
groups everything *open* by shared code surface + shared test target, so one
branch closes one class with one deploy/validate cycle. Demand-gated items are
listed for visibility only — grouping here is NOT a build trigger
(COMPANY_PRINCIPLES Principle 3, BACKLOG.md hard rule).

Status legend: **READY** (validated bug, build anytime) · **BLOCKED** (needs
hardware/decision) · **GATED** (demand-gated, build only on pull).

---

## A. Fix-hint platform correctness — READY

Diagnosis is platform-correct; the remedy text is not. One class, one branch.

| Item | Surface | Test target |
|---|---|---|
| BUG-053 — `ss -tlnp` hint on macOS | hardening hints, heuristics.go | macOS native build |
| BUG-054 — `systemctl`/journald hints on Alpine/OpenRC | hardening + logs hints | Alpine CT210 |
| Audit: all hardcoded `ss` / `systemctl` / `/etc/systemd/*` hint strings | repo-wide grep of hint text | n/a (code review) |
| Minor: "SSH idle timeout not set" INFO on hosts with no sshd | hardening check gate | Alpine CT210 |

Shared work: a platform-aware hint helper (GOOS + init-system branch — init
detection already exists from the Alpine hardening pass). Fix the helper once,
route all hints through it, validate on macOS + CT210 in one pass.

---

## B. ARM real-hardware validation — BLOCKED (needs aarch64 server)

Software pass done (2026-06-10); Graviton2 confirmed CPU id + health clean.
Container-unverifiable paths remain (BUGS.md ARM section, PLATFORM_COVERAGE.md):

1. Thermal — /sys/class/hwmon SoC sensors
2. DMI/SMBIOS — real system product name (`dsd inventory`)
3. SMART on real NVMe/SAS; EDAC/ECC; IPMI/BMC
4. cpufreq governors / per-core scaling on many-core Ampere
5. Ampere SoC implementer id (0x41 vs 0xc0) — pin a fixture from real Altra

Unblock paths: offered Ampere Altra box, Oracle always-free Ampere, or RPi
(partial — covers thermal/cpufreq, not IPMI/EDAC). One SSH session closes the
whole class; keep as a single validation checklist, not five tasks.

---

## C. Cloud-depth collectors — GATED (no cloud customer yet)

Fully specced in BACKLOG.md (AWS Nitro core ~5–6 checks, Azure Hyper-V core
~5–7, full-coverage tiers beyond). Do not build from this index. When a
customer pulls a specific check, build that check only; the customer reveals
which of the core list matters next. Basic cloud *detection* is already
validated (AWS + Azure captures, NVMe-timeout insight).

---

## D. Deferred architecture / features — BLOCKED on decision or demand

| Item | Ref | Gate |
|---|---|---|
| state.Store + JSONL storage (correlation v2 / drift) | Gap Spec 9, CLAUDE.md | Decide before correlation work hardens around stateless assumptions |
| platform.Profile | Spec 8 | Architectural, deferred |
| `dsd capture --cve`, `--timeline` | session notes | Demand |
| containerd standalone detection | session notes | Demand, low priority |
| `--share`/`--push` backend (sanitization lives here, not in capture) | ADR-0002 D6, SHARE_DESIGN.md | Pilot/demand |

---

## E. Recurring audit plays (not tasks — repeatable sweeps)

These found BUG-040–052; re-run after any collector/heuristic change:

1. **False-OK sweep** — "couldn't verify" must never render as OK/green.
   7 grep-able anti-patterns in agent memory `false-ok-bug-class`.
2. **Stale-signal recency gate** — cumulative counters (NRestarts, pstore)
   reported as current. Ask "where else?" — BUG-047/049 hid one file away.
3. **Sibling divergence diff** — same fact, two code paths, two verdicts
   (BUG-050 `cmd/disk.go` vs health thresholds). Diff cmd/* against analysis/.

---

## Housekeeping

- BUGS.md: "Summary — Bugs by Category" + "Testbed Coverage" blocks are
  duplicated with diverging counts (13 vs 14) — delete the older pair.
