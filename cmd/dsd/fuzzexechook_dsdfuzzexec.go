//go:build dsdfuzzexec

package main

// This file only compiles into a binary built with `-tags dsdfuzzexec` — never
// the production dsd binary (no release build, no `go build ./...`, uses this
// tag; see Makefile/scripts). It exists solely so cmd's FuzzCommandAllowlist
// harness can observe and block every command a fuzzed dsd invocation would
// execute, in a real subprocess, without production dsd ever shipping this
// capability or platform.ExecHook ever being non-nil outside a test binary
// built with this tag.

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// execTraceRecord is one exec attempt, appended as a JSON line to the file
// named by DSD_FUZZ_EXEC_TRACE. The fuzz harness reads this back after the
// subprocess exits to run the allowlist and option-injection oracles.
type execTraceRecord struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

var errFuzzExecDenied = errors.New("dsd-fuzz: exec denied by DSD_FUZZ_EXEC_TRACE hook")

func init() {
	logPath := os.Getenv("DSD_FUZZ_EXEC_TRACE")
	if logPath == "" {
		return
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: fuzz-harness-controlled temp path, this binary only exists under the dsdfuzzexec build tag
	if err != nil {
		return
	}
	enc := json.NewEncoder(f)
	platform.ExecHook = func(_ context.Context, name string, args []string) error {
		_ = enc.Encode(execTraceRecord{Name: name, Args: args})
		return errFuzzExecDenied
	}
}
