package collectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// Collector matches runner.Collector exactly.
type Collector interface {
	Name() string
	Timeout() time.Duration
	Collect(ctx context.Context) (any, error)
}

// truncateRunes caps s at max runes (not bytes), appending an ellipsis when it
// truncates. Slicing a string by byte (s[:n]) can cut a multi-byte UTF-8 rune in
// half and emit invalid UTF-8 in a verdict/report line; converting to runes
// first never does. Returns s unchanged when it already fits.
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// runCmd runs an external command with LC_ALL=C and LANG=C so numeric output
// always uses dot as the decimal separator regardless of the user's locale.
// localeSafeEnv returns the process environment forced to the C locale, so any
// external command whose OUTPUT we parse emits stable English/ASCII (month and
// day names, decimal separators, status words) regardless of the host's locale.
// Every external command we parse must use this. runCmd applies it for you;
// raw exec.Command/CommandContext .Output() sites must set cmd.Env =
// localeSafeEnv() — otherwise parsing silently breaks on non-English hosts (e.g.
// `dmesg -T` prints "dom jun" on es_ES, which an English layout cannot parse).
func localeSafeEnv() []string {
	return append(os.Environ(), "LC_ALL=C", "LANG=C")
}

// localeSafeCmd is exec.CommandContext with the C locale forced. Use it for any
// external command whose OUTPUT is parsed when you need the raw *exec.Cmd (e.g.
// .Output() into []byte) rather than runCmd's string return. It keeps every
// parsed command locale-safe by construction; the guard in exec_locale_test.go
// enforces that collectors reach exec only through this / runCmd / runCmdTimeout.
func localeSafeCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = localeSafeEnv()
	return cmd
}

// activeSource is the system-input backend every collector reads through:
// external commands via the runCmd family here, file/sysfs reads via the
// fsaccess.go helpers. The default reads the live system with locale-safe exec.
// `dsd capture --raw` swaps in a source.Recorder; `dsd replay` swaps in a
// source.Replay. See docs/adr/0003-raw-input-capture-replay.md.
var activeSource source.Source = source.Live{Exec: localeSafeExec}

// SetSource swaps the active input backend and returns the previous one so the
// caller can restore it (defer collectors.SetSource(prev)).
func SetSource(s source.Source) source.Source {
	prev := activeSource
	activeSource = s
	return prev
}

// ActiveSource returns the current input backend. `dsd capture --raw` wraps it in
// a source.Recorder so the recorder tees the live, locale-safe exec/read path
// rather than a bare source.Live that would lose LC_ALL=C.
func ActiveSource() source.Source { return activeSource }

// localeSafeExec is the live exec backend: LC_ALL=C, the same force-kill-after-
// cancel semantics runCmd always had, and stdout+stderr+exit captured into a
// source.Result. A non-zero exit is reported via ExitCode with a nil error; only
// a genuine spawn failure (tool absent, ctx cancelled) returns a non-nil error.
func localeSafeExec(ctx context.Context, name string, args ...string) (source.Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = localeSafeEnv()
	cmd.WaitDelay = 100 * time.Millisecond // force-kill after context cancel
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	// cmd.Run() calls Wait() internally on every path, so the child is always
	// reaped — no zombie can leak (see BUG-021).
	err := cmd.Run()
	res := source.Result{Stdout: so.Bytes(), Stderr: se.Bytes()}
	if err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}

// cmdError reports a non-zero exit from runCmd, preserving the long-standing
// contract that any non-zero status comes back as an error (callers only ever
// check err != nil, never the exit code on this path).
type cmdError struct {
	name string
	code int
}

func (e *cmdError) Error() string { return fmt.Sprintf("%s exited %d", e.name, e.code) }

// runCmd runs name through the active source and returns stdout, treating a
// non-zero exit as an error (use runCmdOutput when the exit code itself carries
// findings). The process is killed, not just abandoned, when ctx is cancelled.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	res, err := activeSource.Run(ctx, name, args...)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", &cmdError{name: name, code: res.ExitCode}
	}
	return string(res.Stdout), nil
}

// runCmdOutput is runCmd that KEEPS stdout even when the command exits non-zero.
// Some tools signal FINDINGS via a non-zero exit while writing them to stdout —
// `rpm --verify` (exit 1 = discrepancies/tampering), `dnf check` (exit non-zero =
// broken deps). Use this when a tool reports problems through its exit code and
// parse the returned stdout regardless of err.
func runCmdOutput(ctx context.Context, name string, args ...string) (string, error) {
	res, err := activeSource.Run(ctx, name, args...)
	if err != nil {
		return string(res.Stdout), err
	}
	if res.ExitCode != 0 {
		return string(res.Stdout), &cmdError{name: name, code: res.ExitCode}
	}
	return string(res.Stdout), nil
}

// runCmdCombined runs name with args via the source, returning stdout+stderr
// combined (like exec.Cmd.CombinedOutput) — for tools that emit findings on stderr
// (e.g. resolvectl SERVFAIL/timeout messages). Routed through Source so the output
// is captured and replayed rather than re-run live. Like runCmdOutput, it returns
// the output even on a non-zero exit.
//
//nolint:unused // generic Source helper; currently only linux collectors (dns_resolver) use it
func runCmdCombined(ctx context.Context, name string, args ...string) (string, error) {
	res, err := activeSource.Run(ctx, name, args...)
	combined := string(res.Stdout) + string(res.Stderr)
	if err != nil {
		return combined, err
	}
	if res.ExitCode != 0 {
		return combined, &cmdError{name: name, code: res.ExitCode}
	}
	return combined, nil
}
