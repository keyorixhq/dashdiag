package collectors

// knownViolations is this package's copy of the entry in
// cmd/knownviolations_test.go that TestTLSEndpointBypassesOfflineGate
// (tls_remote_offline_test.go) consults — Go test files can't be shared
// across packages, so this is a deliberate duplicate, not a second source
// of truth. cmd/knownviolations_test.go carries the full description/Issue
// metadata; keep the ID set here in sync with it by hand. Presence here is
// what makes TestTLSEndpointBypassesOfflineGate tolerate (pass on) the
// bypass it proves — remove the ID here and the test fails, even though
// CheckRemoteEndpoint's own behavior hasn't changed.
var knownViolations = map[string]bool{
	"KV-TLS-OFFLINE-BYPASS": true,
}
