package platform

import "context"

// ExecHook, when non-nil, is invoked immediately before every external
// command dsd is about to execute — every production exec.CommandContext call
// site in the repo except internal/fleet's ssh/scp calls, which intentionally
// run outside ResolveTrustedTool's PATH-trust policy to reach an operator's
// own remote tooling (see internal/fleet/fleet.go) and are never part of the
// default diagnostic surface this hook exists to observe.
//
// name is exactly the string the call site is about to pass as the exec'd
// binary (the ResolveTrustedTool-resolved path at nearly every site; a bare
// name at the two call sites that don't resolve it — see
// internal/collectors/collector.go's localeSafeCmd). args is the argv that
// follows it. A non-nil return means "do not run this command" — every call
// site treats it exactly like a genuine exec failure. ExecHook must never be
// used to substitute or alter what would have run; it is observe/deny only.
//
// Production code must never set this. It exists solely so tests and fuzz
// harnesses can record and/or block every command dsd would execute without
// touching the real system.
var ExecHook func(ctx context.Context, name string, args []string) error
