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
func Log(ctx context.Context, component, msg string, kvs ...interface{}) {
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

	fmt.Fprintln(os.Stderr, sb.String())
}

// Logf writes a debug line using a printf-style format string.
// Use Log for key=value pairs; use Logf when you need a free-form message.
func Logf(ctx context.Context, component, format string, args ...interface{}) {
	if !Enabled(ctx) {
		return
	}
	ts := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[debug] %s  %-14s  %s\n", ts, component, msg)
}
