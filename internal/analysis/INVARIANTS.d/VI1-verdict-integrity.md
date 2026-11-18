# VI1 — verdict-integrity invariants (internal/analysis)

These invariants are asserted by the table-driven generator in
`vi1_verdict_integrity_fuzz_test.go` (`FuzzVerdictIntegrity`,
`TestVI1VerdictIntegritySeeds`, `TestVI1FalseOKGaps`) over every check registered
in `verdictChecks`. They hold for ANY correct verdict function and have no
false-positive direction as long as each registry entry encodes true facts about
its check (which monotone metrics it has, which inputs are genuine measurement
gaps). The oracles themselves are red/green-proven in
`vi1_verdict_integrity_redgreen_test.go`.

- **VI1-MONO — monotonicity.** For a registered monotone metric, worsening it by
  a single step must never lower the verdict severity rank
  (OK < INFO < WARN < CRIT). Only genuinely monotone metrics are registered as
  knobs; categorical or non-monotone fields are not.

- **VI1-FALSEOK — no false clean.** A measurement-gap input (a `*Unreadable` /
  `*Unverified` sentinel set, an unreachable mount, an unenumerable drive list)
  must produce at least one insight with `Unverified == true` — never an empty
  (silent confident OK) result. This is the false-clean bug class
  (#575/#576/#921); the authoritative sentinel surface is
  `internal/models/falseok_signal_registry_test.go`.

- **VI1-IDEM — idempotence.** Running a check twice on the same input yields
  `reflect.DeepEqual` insights (the check is a pure function of its input).

- **VI1-ORDER — order independence of aggregation.** Permuting a check's
  aggregated input slice (filesystems, drives) yields the same multiset of
  `(Level, Check)` verdict pairs. The exact message TEXT is intentionally NOT
  asserted order-invariant: an aggregated insight may embed a host-derived name
  list joined in input order (see the `checkNVMe` determinism lead in the VI1
  report). Reordering that drops/adds a finding or changes a severity still trips
  the multiset.

- **VI1-RESOURCE — bounded cost.** Each check run stays within the shared DL1
  resource budget (`internal/testutil/resource`: Go-heap `TotalAlloc` + wall
  time). These checks are pure in-memory functions, so only those two meters
  matter; fd/network/goroutine meters are not enabled here.

If a registered knob or gap case turns out to encode a wrong premise, fix the
registry entry (or quarantine the check) — never weaken the oracle to match
observed behaviour.
