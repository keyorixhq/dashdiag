package collectors

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"
)

// Collector matches runner.Collector exactly.
type Collector interface {
	Name() string
	Timeout() time.Duration
	Collect(ctx context.Context) (interface{}, error)
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

// The process is killed (not just abandoned) when ctx is cancelled.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = localeSafeEnv()
	cmd.WaitDelay = 100 * time.Millisecond // force-kill after context cancel
	var out bytes.Buffer
	cmd.Stdout = &out
	// cmd.Run() calls Wait() internally on every path (success, non-zero exit, and
	// context cancel + WaitDelay force-kill), so the child is always reaped — no
	// zombie can leak here. See BUG-021: investigation found no Start()-without-Wait()
	// anywhere in the tree; transient <defunct> in ps is a sampling artifact.
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}
