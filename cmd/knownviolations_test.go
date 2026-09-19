package cmd_test

// knownviolations_test.go is the explicit, reviewed list of deviations the
// read-only-invariant oracles (FuzzCommandAllowlist, the writes-contract
// check inside it, and TestTLSEndpointBypassesOfflineGate in
// internal/collectors) are told to tolerate instead of failing. Anything NOT
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
	"KV-TLS-OFFLINE-BYPASS": {
		ID:          "KV-TLS-OFFLINE-BYPASS",
		Issue:       "TBD — draft in STEP 2 report, bug/medium",
		Description: "internal/collectors/tls_remote.go's CheckRemoteEndpoint (dsd tls --endpoint host:port) does not check platform.NetworkAllowed()/DSD_OFFLINE before dialing — the only remote-dialing code path in the repo that doesn't. FuzzCommandAllowlist never drives `dsd tls` (a live dial isn't safe to fuzz); TestTLSEndpointBypassesOfflineGate (internal/collectors/tls_remote_offline_test.go) demonstrates it deterministically against a loopback listener instead.",
	},
	"KV-PING-ROUTE-UNRESOLVED": {
		ID:          "KV-PING-ROUTE-UNRESOLVED",
		Issue:       "TBD — draft in STEP 2 report, enhancement (folds into the exec-site consolidation issue)",
		Description: "internal/collectors/network_quick.go's localeSafeCmd (ping, route -n get default) execs the bare name, not platform.ResolveTrustedTool(name) — the only two of the ~10 exec call sites that skip PATH-trust resolution. Recorded ExecHook name is therefore not a resolved path for these two.",
	},
}
