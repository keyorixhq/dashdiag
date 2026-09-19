package cmd_test

// knownviolations_test.go is the explicit, reviewed list of deviations the
// read-only-invariant oracles (FuzzCommandAllowlist and the writes-contract
// check inside it) are told to tolerate instead of failing. Anything NOT
// listed here that trips an oracle is FATAL — this file exists so a
// tolerated deviation is a reviewed, keyed, one-line decision, never a silent
// carve-out buried in oracle logic. Each entry is kept OPEN until the linked
// GitHub issue closes; removing an entry (or narrowing it) is how a fix gets
// re-covered by the oracle instead of just deleted from this list.
//
// IDs are placeholders (KV-*) until the corresponding issues are filed (see
// the STEP 2 report); update the Issue field with the real number once filed.
type knownViolation struct {
	ID          string
	Issue       string // "keyorixhq/dashdiag#NNN" once filed; placeholder text until then
	Description string
}

var knownViolations = map[string]knownViolation{
	"KV-HOME-FAILOPEN-BASELINE": {
		ID:          "KV-HOME-FAILOPEN-BASELINE",
		Issue:       "TBD — draft in STEP 2 report, bug/low",
		Description: "internal/baseline/baseline.go:68 baselineDir() does not guard os.UserHomeDir()'s error; an unset/unresolvable $HOME makes baseline snapshot writes land at CWD-relative ./.dsd/baselines instead of failing closed.",
	},
	"KV-HOME-FAILOPEN-GOLDEN": {
		ID:          "KV-HOME-FAILOPEN-GOLDEN",
		Issue:       "TBD — draft in STEP 2 report, bug/low",
		Description: "internal/baseline/golden.go:12 goldenDir() has the same unguarded os.UserHomeDir() fail-open as baseline.go:68, for `dsd`'s golden-baseline save path.",
	},
	"KV-HOME-FAILOPEN-SECBASELINE": {
		ID:          "KV-HOME-FAILOPEN-SECBASELINE",
		Issue:       "TBD — draft in STEP 2 report, bug/low",
		Description: "internal/baseline/security_baseline.go:64 SecurityBaselinePath() has the same unguarded os.UserHomeDir() fail-open, for `dsd security --save-baseline`.",
	},
	"KV-PING-ROUTE-UNRESOLVED": {
		ID:          "KV-PING-ROUTE-UNRESOLVED",
		Issue:       "TBD — draft in STEP 2 report, enhancement (folds into the exec-site consolidation issue)",
		Description: "internal/collectors/network_quick.go's localeSafeCmd (ping, route -n get default) execs the bare name, not platform.ResolveTrustedTool(name) — the only two of the ~10 exec call sites that skip PATH-trust resolution. Recorded ExecHook name is therefore not a resolved path for these two.",
	},
}
