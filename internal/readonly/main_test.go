//go:build linux

package readonly

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// execRecorder captures every command dsd attempts to run, via platform.ExecHook
// (the only seam that sees the fully-resolved name+args of every collector exec —
// $PATH shims cannot, because ResolveTrustedTool ignores $PATH by design). The
// hook DENIES every command: nothing dsd routes through its exec layer ever runs
// on this unsandboxed host, so even a mutating command a collector *tried* to run
// is observed and blocked, never executed.
type execRecorder struct {
	mu    sync.Mutex
	execs []execTrace
}

type execTrace struct {
	Name string
	Args []string
}

var recorder = &execRecorder{}

// errExecDenied makes the exec fail exactly like a genuine spawn failure, so the
// collector degrades along its tool-absent path.
var errExecDenied = fmt.Errorf("ro1-readonly: exec denied and recorded")

func (r *execRecorder) hook(_ context.Context, name string, args []string) error {
	r.mu.Lock()
	cp := make([]string, len(args))
	copy(cp, args)
	r.execs = append(r.execs, execTrace{Name: name, Args: cp})
	r.mu.Unlock()
	return errExecDenied
}

func (r *execRecorder) reset() {
	r.mu.Lock()
	r.execs = r.execs[:0]
	r.mu.Unlock()
}

func (r *execRecorder) snapshot() []execTrace {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]execTrace, len(r.execs))
	copy(out, r.execs)
	return out
}

// shimTracePath names the file the PATH recording shims append to. The shims are
// a SECONDARY net: they only ever fire for an exec that bypasses platform.ExecHook
// and does its OWN $PATH lookup (Go stdlib, cgo, a third-party library) — every
// one of dsd's own collector execs is denied by the hook before any spawn, so a
// shim firing at all is itself worth reporting.
var shimTracePath string

// dangerousShimBinaries are mutating/destructive binaries that are NOT on the
// read-only allowlist. A shim is written for each so that if any code path
// (stdlib/cgo/third-party) ever execs one via $PATH, it is recorded here instead
// of running the real tool.
var dangerousShimBinaries = []string{
	"rm", "rmdir", "mv", "cp", "dd", "tee", "truncate", "shred", "mkfs",
	"mount", "umount", "swapon", "swapoff", "chmod", "chown", "ln", "sed",
	"reboot", "shutdown", "halt", "poweroff", "kexec", "sh", "bash", "env",
}

// buildShimDir writes a recording shim for every allowlisted binary and every
// dangerous binary, points $PATH at the shim dir alone, and returns the dir. The
// shims append "<name>\t<args>" to $DSD_RO1_SHIM_TRACE and exit 0 with no output.
func buildShimDir() (string, error) {
	dir, err := os.MkdirTemp("", "ro1-shims-")
	if err != nil {
		return "", err
	}
	names := make(map[string]bool)
	for b := range readOnlyBinaries {
		names[b] = true
	}
	for _, b := range dangerousShimBinaries {
		names[b] = true
	}
	script := "#!/bin/sh\n" +
		"printf '%s\\t%s\\n' \"$(basename \"$0\")\" \"$*\" >> \"$DSD_RO1_SHIM_TRACE\"\n" +
		"exit 0\n"
	for name := range names {
		p := filepath.Join(dir, name)
		if werr := os.WriteFile(p, []byte(script), 0o755); werr != nil { //nolint:gosec // executable shim, intentional
			return "", werr
		}
	}
	return dir, nil
}

// readShimTrace returns the lines the shims recorded this input, then truncates
// the file for the next input. Safe because the whole run+assert body is
// serialised by runMu.
func readShimTrace() []string {
	data, err := os.ReadFile(shimTracePath) // #nosec G304 -- harness temp path
	if err != nil {
		return nil
	}
	_ = os.Truncate(shimTracePath, 0)
	out := append([]string(nil), splitNonEmptyLines(string(data))...)
	sort.Strings(out)
	return out
}

// runMu serialises each fuzz input's run+assert critical section. The exec
// recorder, net guard and shim trace are process-global (platform.ExecHook,
// http.DefaultTransport and net.DefaultResolver are single globals), so with
// `-parallel 2` two workers would otherwise interleave their traces and make the
// oracles unsound. Each input is sub-second (every real exec is denied), so the
// cost of serialising is small and the oracles stay per-input exact.
var runMu sync.Mutex

func TestMain(m *testing.M) {
	// 1. Network guard: non-loopback dials via http.DefaultTransport /
	//    net.DefaultResolver are recorded and denied.
	installNetGuard()

	// 2. Exec oracle: observe+deny every command dsd attempts.
	platform.ExecHook = recorder.hook

	// 3. PATH recording shims (secondary net for non-hook $PATH execs).
	shimDir, err := buildShimDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ro1: building shim dir:", err)
		os.Exit(1)
	}
	traceFile, err := os.CreateTemp("", "ro1-shimtrace-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ro1: creating shim trace:", err)
		os.Exit(1)
	}
	shimTracePath = traceFile.Name()
	_ = traceFile.Close()
	os.Setenv("PATH", shimDir)
	os.Setenv("DSD_RO1_SHIM_TRACE", shimTracePath)

	// 4. Persistent watched-host sentinel tree (outside every per-input temp dir).
	hostDir, err := buildWatchedHostDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ro1: building watched host dir:", err)
		os.Exit(1)
	}
	watchedHostDir = hostDir

	code := m.Run()

	platform.ExecHook = nil
	_ = os.RemoveAll(shimDir)
	_ = os.Remove(shimTracePath)
	_ = os.RemoveAll(hostDir)
	os.Exit(code)
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if line := s[start:i]; line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if line := s[start:]; line != "" {
		out = append(out, line)
	}
	return out
}
