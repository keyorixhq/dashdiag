# INVARIANTS — MC4 target: viper config differential at full 1 MiB + services

Target: `internal/thirdpartyfuzz/viperconf` · `FuzzViperConfigFull` (extends MC1
`FuzzViperConfigDifferential`).

Scope: the viper decode + key-folding + `Unmarshal` + `Validate` core of
`internal/config.Load`, now exercised at the FULL 1 MiB implicit-config loader
cap, with a `[]Services`-aware differential and a TOML/INI duplicate-key +
include-directive seed space. Closes MC1 LEFTOVERs 2 (differential capped at
128 KiB; `[]Services` decoded+Validated but never Get-compared; duplicate-key /
include space not seeded).

- **V1 no panic / typed error.** Same as MC1, now at up to 1 MiB.
- **V2 bounded cost.** `resource.Check` (alloc factor 1024 + 5 s TimeBudget) runs
  on every input. The LINEAR backends (json/toml/ini/env) are exercised to the
  full 1 MiB; YAML is sub-capped INSIDE this target to 128 KiB so the KNOWN O(n²)
  sibling-key decode (F1, characterised offline) does not re-trip V2 at ~1 MiB and
  drown a NEW super-linear blow-up. V2 therefore still catches a new blow-up in
  the linear formats at full size; the YAML quadratic is reported, not asserted.
- **V3 scalar differential.** Same as MC1 (viper `GetFloat64`/`GetInt` on the
  canonical key agrees with the decoded struct field), now at full size.
- **V4 services differential (NEW).** When `Unmarshal`+`Validate` ACCEPT a doc,
  viper's own raw slice view (`v.Get("services")[i]`) agrees with the decoded
  `config.Config.Services[i]` on the dial-target fields (port, protocol, host,
  name). A divergence means `Validate` blessed one outbound dial target while a
  viper-reading consumer would act on another — the slice-path analog of the V3
  footgun class. Compared only when both views carry entries (ini/env decode no
  array-of-tables, so `cfg.Services` is empty there — nothing to diff).

Seeds added: TOML duplicate keys (spec-forbidden → typed error path), INI
duplicate + case-fold-duplicate keys (tolerant → differential must stay
consistent), `include`/`!include` directives across yaml/toml/ini (inertness:
the key round-trips as the literal string, i.e. viper does not expand it into a
file read), YAML merge-key/anchor/alias, multi-element services, and small
quadratic-region shapes the fuzzer grows.

Red/green: V3 — struct value forced to diverge from the viper store → fired
(MC1). V4 — forcing `cfg.Services[i].Port` to differ from the viper raw element
fires `V4 services[i].port differential` (scratch proof, reverted). V2 — factor-0
budget on a 40k-key JSON doc fires time/alloc (scratch, reverted).

Does NOT verify (beyond MC1's list): that viper REJECTS every malformed doc for
the right reason; that an include key triggers NO filesystem read via a syscall
trace (asserted indirectly by the literal round-trip); the YAML quadratic itself
(bounded out, characterised offline in `.scratch/upstream-drafts/`); formats the
task does not call out (properties/hcl).
