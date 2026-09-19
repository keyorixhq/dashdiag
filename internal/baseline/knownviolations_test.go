package baseline

// knownViolations is this package's copy of the entries in
// cmd/knownviolations_test.go that TestHomeFailOpen_KnownViolations
// consults — Go test files can't be shared across packages, so this is a
// deliberate duplicate, not a second source of truth. cmd/knownviolations_test.go
// carries the full description/Issue metadata; keep the ID set here in sync
// with it by hand. Presence in this map is what makes
// TestHomeFailOpen_KnownViolations tolerate (pass on) the fail-open
// behavior it proves — remove an ID here and the matching subtest fails,
// even though the underlying baselineDir/goldenDir/SecurityBaselinePath
// code hasn't changed, exactly the "delete entry -> fails" property the
// registry exists to give.
var knownViolations = map[string]bool{
	"KV-HOME-FAILOPEN-BASELINE":    true,
	"KV-HOME-FAILOPEN-GOLDEN":      true,
	"KV-HOME-FAILOPEN-SECBASELINE": true,
}
