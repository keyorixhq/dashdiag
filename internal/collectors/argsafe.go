package collectors

import (
	"context"
	"fmt"
	"regexp"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// Argument handling for host tools.
//
// Several collectors pass values that were read from the host (unit names parsed
// from systemctl output, interface and device names, VM names, paths) as
// arguments to an external tool. A value that begins with '-' would be parsed by
// the tool as an option rather than as an operand. Two complementary measures
// keep that from happening:
//
//   - where the tool honours the POSIX end-of-options marker, the operand is
//     preceded by "--" (systemctl, grep, du, ls, readelf, rpm, dpkg);
//   - every host-derived value is validated against a strict pattern first, and
//     the call is skipped (an error is returned, which every caller already
//     treats as "tool unavailable") when it does not match. This is the only
//     measure for tools that do not accept "--" (ethtool, ip, iwconfig, nvme,
//     virsh, ...).
//
// Neither adds a command: argv is at most the previous read-only invocation
// plus a "--", or the call is skipped.

// unsafeArgError reports that a host-derived value was refused before exec.
type unsafeArgError struct {
	kind  string
	value string
}

func (e *unsafeArgError) Error() string {
	return fmt.Sprintf("skipped: unsafe %s %q", e.kind, truncateRunes(e.value, 64))
}

func newUnsafeArg(kind, v string) error { return &unsafeArgError{kind: kind, value: v} }

var (
	reIfaceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:@+-]*$`)
)

// validUnitName reports whether s is a conservative systemd unit name: only
// [A-Za-z0-9:_.\@-] and never a leading '-'.
func validUnitName(s string) bool {
	return platform.ValidUnitName(s)
}

// validIfaceName reports whether s is a conservative network interface name
// (no leading '-', no whitespace/control characters, at most 64 bytes).
func validIfaceName(s string) bool {
	return len(s) <= 64 && reIfaceName.MatchString(s)
}

// validOperand reports whether s is safe to hand to a tool as a positional
// operand (device node, path, VM/pool/network name, package): non-empty, no
// leading '-', and no control characters. Deliberately permissive otherwise, so
// legitimate names are never skipped.
func validOperand(s string) bool {
	if s == "" || len(s) > 4096 || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// cmdRunFn is the signature shared by runCmd, runCmdOutput and runCmdCombined.
type cmdRunFn func(ctx context.Context, name string, args ...string) (string, error)

// runSystemctl runs `systemctl <opts...> -- <units...>` through run. Every unit
// is validated first; if any is not a conservative unit name nothing is
// executed and an error is returned. opts must not contain unit names.
func runSystemctl(ctx context.Context, run cmdRunFn, opts []string, units ...string) (string, error) {
	for _, u := range units {
		if !validUnitName(u) {
			return "", newUnsafeArg("systemd unit name", u)
		}
	}
	args := make([]string, 0, len(opts)+1+len(units))
	args = append(args, opts...)
	args = append(args, "--")
	args = append(args, units...)
	return run(ctx, "systemctl", args...)
}

// guarded runs fn only when v passes ok; otherwise nothing is executed and an
// error naming kind is returned (callers already treat any error as "tool
// unavailable / value unreadable"). It is for tools that do not accept "--":
// argv is unchanged, the host-derived value is just refused when option-shaped.
func guarded(ok func(string) bool, kind, v string, fn func() (string, error)) (string, error) {
	if !ok(v) {
		return "", newUnsafeArg(kind, v)
	}
	return fn()
}
