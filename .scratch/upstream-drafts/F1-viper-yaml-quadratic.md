# UPSTREAM DRAFT (NOT SENT) — go.yaml.in/yaml/v3: mapping decode is O(n²) in sibling-key count

Target project: **go.yaml.in/yaml/v3** (the YAML decoder viper v1.21's YAML codec
calls). Secondary note to **spf13/viper**: viper is NOT the quadratic source;
this draft documents the bisection so viper maintainers can point users upstream.

Status: DRAFT, held locally (unattended run — nothing is sent). Reproducer is
stand-alone at `./F1-repro/` in this directory.

## Summary

Decoding a YAML mapping with N sibling keys into a Go map takes time **O(N²)**,
while allocations are O(N). At realistic config sizes this is a denial-of-service
amplifier: a ~1 MiB YAML file of flat keys takes tens of seconds of CPU to
decode, with no corresponding memory signal to trip a limiter.

## Measurements (go1.27.4, 2 cores, `-benchtime=1x`)

Flat mapping `k0: 0\nk1: 1\n…` of N keys.

| keys N | (A) raw yaml/v3 decode | (B) viper ReadConfig(yaml) | (C) viper ReadConfig(json) |
|-------:|-----------------------:|---------------------------:|---------------------------:|
| 1 000  | 5.86 ms                | 7.21 ms                    | 1.03 ms                    |
| 2 000  | 11.8 ms                | 20.3 ms                    | 1.90 ms                    |
| 4 000  | 48.3 ms                | 68.1 ms                    | 3.87 ms                    |
| 8 000  | 299 ms                 | 285 ms                     | 7.49 ms                    |
| 16 000 | 924 ms                 | 987 ms                     | 15.6 ms                    |
| 32 000 | 5 457 ms               | 5 314 ms                   | 34.7 ms                    |

Allocs (A): 12 544 → 415 806 over the same range — **linear** (≈13× per 32× keys).

- 1k→32k is a **32×** increase in keys. Linear would be ~32×; quadratic ~1024×.
  Raw yaml/v3 (A) grows **931×**, viper/yaml (B) **738×** — both ≈ O(N²).
- viper/yaml (B) tracks raw yaml/v3 (A) within ~15% at every size. The extra cost
  of viper's `insensitiviseMap` key-fold + flatten is a small, roughly-linear
  constant on top of the decode.
- viper/json (C), which runs the **same** viper `insensitiviseMap`/flatten over an
  equally large key set, is **linear** (33.7× for 32× keys).

## Bisection conclusion

The quadratic is in the **go.yaml.in/yaml/v3 mapping decode**, not viper. Proof:
(1) the raw library decode (A) is already quadratic with no viper involved; (2)
viper's own fold/flatten is exercised identically by the JSON path (C), which is
linear, so fold/flatten is not the O(N²) term; (3) B ≈ A at every size.

Time is quadratic while allocations are linear → the cost is repeated CPU work
per key, not memory growth. This is consistent with the mapping decoder doing
O(N) work for every one of the N keys (e.g. a per-key scan of already-decoded
keys for duplicate-key detection / merge-key resolution). The exact hot loop is
for the maintainers to confirm; the reproducer isolates it to a plain
`yaml.Unmarshal(flatMapBytes, &map[string]interface{}{})` with no merge keys and
no anchors, so duplicate-key handling is the most likely locus.

## Why it matters

A YAML document is frequently untrusted or semi-trusted (a config file an
operator may not have authored line-by-line; in agentic/MCP contexts, content a
model ingested). O(N²) decode with O(N) memory means a small file (≈1 MiB ≈
~100k short keys) costs tens of seconds of CPU with no memory-limiter signal — a
cheap CPU-exhaustion primitive against any service that YAML-decodes caller input.

## Reproducer

`./F1-repro/main.go` (stand-alone module). Prints the decode time for each N and
the per-doubling ratio; a ratio trending toward 4× per doubling is the quadratic.

```
cd F1-repro && go run .
```

Expected: ratios climb toward ~4× per key-doubling for YAML, ~2× for JSON.

## Suggested fixes (upstream)

- In the mapping decoder, build keys into the destination map with O(1)
  membership checks instead of an O(N) scan per key for duplicate detection.
- Failing an upstream fix, document the quadratic and recommend callers cap YAML
  input size (see the downstream dsd proposal, `.scratch/proposals/`, which caps
  `--config` input before it reaches viper).

## Downstream (dsd) relationship

dsd reaches this via `internal/config.Load` → viper → yaml/v3. The IMPLICIT
`$HOME/.dsd.yaml` path is already capped at 1 MiB (`maxImplicitConfigBytes`);
the EXPLICIT `--config` path is UNcapped today. The companion proposal
`.scratch/proposals/config-size-cap.patch` adds a parallel cap to the explicit
path so neither entry point can feed viper a quadratic-sized YAML.
