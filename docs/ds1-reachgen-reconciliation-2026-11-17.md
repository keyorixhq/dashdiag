# DS1 reachgen reconciliation pass (2026-11-17)

A reachability-first reconciliation of DashDiag's third-party fuzz coverage,
re-running keyorix's `reachgen` tool (reachability-first harness lead generator)
against this module to confirm or deny a *marginal* coverage gap after the
original DS1 pass (five promoted targets, see CHANGELOG 2.7.1-dev "DS1").

**Result: no new target promoted.** reachgen surfaces no currently-uncovered,
untrusted-reachable third-party call site that clears the oracle bar. The
existing 111 `Fuzz` functions already close the gap reachgen points at. This is
a confirmation of the going-in assumption, not a null run — the evidence is
below.

## reachgen headline numbers (DashDiag full module, `-patterns ./...`)

| Metric | Count |
|---|---:|
| Distinct third-party exported funcs DashDiag calls | 62 |
| …with ≥1 untrusted-provenance call site | 10 |
| …already covered by an existing `Fuzz` (reachgen `MarkCovered`) | 6 |
| …**uncovered** untrusted entries (reachgen's lead list) | 4 |
| Package load diagnostics | 0 |
| Test-support packages correctly skipped | 1 (`internal/testutil/resource`) |
| **New targets promoted after hand cross-reference** | **0** |

Run: `reachgen -dir . -patterns ./... -top 100 -coverroot . [-include-covered]`
(tool built from the read-only keyorix clone; offline, read-only; 0 load errors).

## The 4 "uncovered" leads — hand cross-reference

None is a genuine new lead:

1. **`spf13/viper Viper.ReadConfig(io.Reader)`** — *reachgen coverage
   false-negative.* Its only call site is `internal/thirdpartyfuzz/viperconf/
   doc.go:19` (`readConfigBytes`), which is the production-side helper that
   `FuzzViperConfigDifferential` drives. ReadConfig is therefore the direct
   subject of that target (V1 no-panic / V2 bounded-work / V3 validator-vs-viper
   differential, all five config formats). reachgen's token coverage heuristic
   missed it: the `ReadConfig` identifier appears in the test file only in
   comments and as the wrapped `readConfigBytes` call, so the lower-cased AST
   token `readconfig` never matches `readconfigbytes` — exactly the loose-match
   limitation its README documents.

2. **`spf13/viper Viper.SetConfigFile(string)`** — pure setter
   (`internal/config/config.go:149,168`). It stores a path; it parses no
   untrusted *content*. The parse path it feeds (`ReadInConfig`/`ReadConfig`) is
   already covered by `FuzzViperConfigDifferential`. Nothing to oracle.

3. **`prometheus-community/pro-bing NewPinger(string)`**
   (`network_quick.go:516`, `network_deep.go:74`). `NewPinger(addr)` is
   `New(addr)` + `p.Resolve()`, and `Resolve()` performs DNS / network I/O — so a
   fuzz harness over it is neither hermetic nor bounded-work, and the
   pro-bing-specific logic it adds over `net.ResolveIPAddr` is trivial. pro-bing's
   real untrusted surface — ICMP reply accounting of attacker-shaped packets — is
   already covered by `FuzzProBingReplyAccounting`
   (`internal/collectors/probing_reply_fuzz_test.go`).

4. **`charmbracelet/bubbletea NewProgram(tea.Model, []tea.ProgramOption)`** —
   TUI program constructor; args are an interface + an options slice (reachgen
   marks it `Fuzzable: no`). No untrusted-byte parsing surface; the
   `request-body` label is laundered from a string that reached the model, not a
   parser input.

## Named candidate leaf libs (from the DS1 plan)

- **`skip2/go-qrcode New(string, RecoveryLevel)`** — 1 untrusted site
  (`internal/output/qr.go:27`); reachgen correctly marks it **covered** by
  `FuzzQRCodeRoundTrip` (full independent QR decoder, round-trip + ISO-18004
  conformance + bounded-size/idempotence oracles).
- **`go.yaml.in/yaml/v4 Unmarshal([]byte, any)`** — 2 sites, 1 untrusted
  (`internal/yamlsafe/yamlsafe.go:29`; the other, `cmd/demo.go:81`, is a static
  embedded fixture); reachgen correctly marks it **covered** by
  `FuzzYAMLSafeDiffAndBound` (yamlsafe-vs-plain differential + #510 bounded-cost
  oracle) and transitively by the viper config target.
- **`go.yaml.in/yaml/v3`** — **no direct DashDiag call site** (indirect dep,
  reached only transitively via viper/mapstructure). reachgen found zero sites;
  nothing to target directly. Correct.
- **`xml-roundtrip-validator`** — **not a dependency** of this module (absent
  from `go.mod`/`go.sum`). Dropped; no target invented.

## reachgen tool health (first use against a non-keyorix module)

reachgen ran cleanly against a second module: it built unmodified, loaded every
package with full type info (0 load diagnostics), correctly skipped the one
test-support package, and produced a plausible ranked table. One imprecision
worth noting for reuse — **not a crash or a blocker**: the coverage column is a
loose import+token match and produced a false-negative on `Viper.ReadConfig`
(lead 1 above). This is the documented "coverage is a hint, re-checked by hand"
limitation, and the re-check is what this reconciliation did. No tool change
required; the "uncovered" column must be hand-verified, as the README states.
