# INVARIANTS — PD1 target: internal/config.Load fail-closed

Target: `internal/config` · `FuzzConfigLoadFailClosed`.

Scope: `config.Load(explicit_path)` — the `--config` / explicit-path branch of the
loader (not the implicit `$HOME/.dsd.yaml` gating, which is tested in `config_test.go`).
The loaded bytes drive spf13/viper + go.yaml.in/yaml + go-viper/mapstructure.

- **P1 fail-closed / Validate invariant.** `Load(path)` returning `(cfg, nil)` implies
  `cfg.Validate() == nil`. A config that fails validation is surfaced as an error, never
  silently accepted. Covers: NaN/Inf/negative thresholds, out-of-range ports, missing
  service fields, unsupported protocol.
- **P2 bounded allocation.** `Load` stays within `resource.Check` budget
  (factor 640 × inputLen + 1 MiB floor, 5 s wall time) for all inputs. Calibrated
  baselines: flat valid config ~1065× at 32 B (absorbed by floor), 2000-entry services
  ~103× at 74 KB, 200 KB scalar ~9×, `[[[[` bracket-nest ~371× at 4 KB, `{{{`
  flow-mapping-nest ~616× raw / 504× effective peaking at 10 KB then plateauing at
  ~6.1 MB (go-yaml internal depth limit — DSCFG1 report). Factor 640 tolerates all of
  these while tripping the go.yaml #510 duplicate-key O(n²): 1 KB → 11 MB >>
  factor-640 budget of 1.7 MB (6.7× over).
- **P3 no goroutine leak.** `GoroutineDiff ≤ 16` per call.
- **P4 no disk write.** `resource.AssertUnchanged` on the temp config dir proves `Load`
  writes nothing back (not even a viper-internal cache).

Known degenerate shapes (all linear / bounded, tolerated by factor 640):
- `[[[[` bracket-nest: O(n) sequence-nesting, ~371× at 4 KB.
- `{{{` flow-mapping-nest: O(n) flow-map-nesting, peaks ~616× raw at 10 KB then caps
  at ~6.1 MB (DSCFG1). Distinct from the duplicate-key quadratic (#510).

Known unguarded defect (not assertable, still detectable):
- go.yaml #510 duplicate-key O(n²): `a: 1\na: 1\n…` at 1 KB → ~11 MB, three orders
  of magnitude above the 640× budget — the oracle still fires for it.

Red/green: factor set to 0 on a 4000-byte brace input → P2 fires; factor 640 →
passes. Secret-echo guard not tested here (no error-text oracle in this target).
