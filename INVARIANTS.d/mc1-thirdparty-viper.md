# INVARIANTS — MC1 third-party target: spf13/viper

Target: `internal/thirdpartyfuzz/viperconf` · `FuzzViperConfigDifferential`.

Scope: the viper decode + key-folding + `Unmarshal` + `Validate` core of
`internal/config.Load`, across yaml/json/toml/ini/env. The file-discovery,
symlink and size-cap gates are `internal/config`'s own (tested in
`config_test.go`) and out of scope.

- **V1 no panic / typed error.** Neither `ReadConfig`, `Unmarshal` nor `Validate`
  panics on any bytes/format; a rejected file returns a Go error.
- **V2 bounded cost.** Decode+unmarshal+validate stay within the shared resource
  oracle (alloc factor 1024 + time + goroutines) for every input up to the fuzz
  input cap (128 KiB — see note on the YAML quadratic).
- **V3 validator/consumer differential.** Whenever `Unmarshal`+`Validate` accept a
  document, viper's own key store (`GetFloat64`/`GetInt` on the canonical key —
  what a consumer reading viper directly sees) agrees with the decoded
  `config.Config` field (what `Validate` judged and the collectors use). A
  divergence is the case-fold / delimiter / duplicate-key footgun class.

Known finding (reported, not asserted): viper's YAML backend decode is O(n²) in
sibling-key count (CANDIDATE `mc1-viper-yaml-quadratic`); JSON is linear. The fuzz
input is capped at 128 KiB so V2 explores new behaviour instead of re-tripping on
this.

Red/green: struct value forced to diverge from the viper store → V3 fired;
factor-0 budget on a 40k-key doc → V2 fired (scratch removed).
