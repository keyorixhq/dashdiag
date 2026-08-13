// Package debug provides lightweight debug logging for DashDiag.
//
// Usage:
//
//	ctx = debug.With(ctx, true)          // enable debug mode
//	debug.Log(ctx, "Network", "pingRTT", "host", "8.8.8.8", "ms", 0.6)
//
// Output goes to stderr only, so --json stdout stays clean.
// Format: [debug] 15:04:05.000  Component       message  key=value key=value
package debug

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
)

// ctxKey is unexported so nothing outside this package can forge a debug context.
type ctxKey struct{}

// With returns a new context with debug mode set to enabled.
func With(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, ctxKey{}, enabled)
}

// Enabled reports whether debug mode is active in ctx.
func Enabled(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKey{}).(bool)
	return v
}

// Log writes a debug line to stderr if debug mode is active.
//
// component — subsystem name, e.g. "Network", "Runner", "Analysis"
// msg       — short description of what happened
// kvs       — optional alternating key, value pairs
//
// Example:
//
//	debug.Log(ctx, "Network", "pingRTT skip", "host", "192.168.1.1", "err", err)
func Log(ctx context.Context, component, msg string, kvs ...any) {
	if !Enabled(ctx) {
		return
	}

	ts := time.Now().Format("15:04:05.000")
	var sb strings.Builder

	fmt.Fprintf(&sb, "[debug] %s  %-14s  %s", ts, component, msg)

	// Append key=value pairs.
	for i := 0; i+1 < len(kvs); i += 2 {
		fmt.Fprintf(&sb, "  %v=%v", kvs[i], kvs[i+1])
	}
	// If an odd kv was passed, surface it so we notice the bug.
	if len(kvs)%2 != 0 {
		fmt.Fprintf(&sb, "  MISSING_VALUE_FOR=%v", kvs[len(kvs)-1])
	}

	// Every kv value here can ultimately originate from the host being
	// diagnosed (err strings from failed probes/subprocess calls, hostnames/
	// IPs from the routing table, etc.) — --debug is exactly the mode an
	// operator reaches for when investigating a host they suspect is broken
	// or hostile. Strip control characters (including embedded newlines,
	// which could forge a fake "[debug] ..." line, and ESC, which starts
	// ANSI/OSC terminal escape sequences) before this reaches the operator's
	// terminal.
	fmt.Fprintln(os.Stderr, stripControl(sb.String()))
}

// Logf writes a debug line using a printf-style format string.
// Use Log for key=value pairs; use Logf when you need a free-form message.
func Logf(ctx context.Context, component, format string, args ...any) {
	if !Enabled(ctx) {
		return
	}
	ts := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	// Same rationale as Log above: args can carry attacker-influenced text
	// from the diagnosed host — strip control/ANSI-escape bytes (including
	// embedded newlines) before this reaches the operator's terminal.
	line := fmt.Sprintf("[debug] %s  %-14s  %s", ts, component, msg)
	fmt.Fprintln(os.Stderr, stripControl(line))
}

// stripControl removes control characters (including ESC, which starts
// ANSI/OSC/DCS terminal escape sequences, and \n/\r, which could forge a
// fake "[debug] ..." line) from s, leaving printable text unchanged. debug/
// is imported by collectors/ and runner/, both restricted by CLAUDE.md's
// layered-import contract to a narrow allowlist that doesn't include
// internal/output, so this duplicates the small amount of logic in
// output.SanitizeControl rather than adding a new cross-package import.
func stripControl(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
