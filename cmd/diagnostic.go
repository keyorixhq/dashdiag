package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// diagnostic describes a standard collector-backed diagnostic command. The whole
// point is that runDiagnostic owns the cross-cutting contracts in ONE place —
// mode detection, progress, collection, the exit-code recording, and the
// --json / human split — so a command built this way CANNOT silently violate
// them. That is the structural answer to BUG-022 / #74 / the --plain leak: the
// invariant is satisfied by construction, not by remembering.
//
// Commands with a fundamentally different shape (health's policy/CVE pipeline,
// tls's remote endpoints, fleet's multi-host fan-out, the --watch loops) stay
// bespoke and are covered by the contract guard in contract_test.go.
type diagnostic struct {
	label   string
	timeout time.Duration
	cols    []runner.Collector
	// jsonValue returns the value to marshal for --json (e.g. the primary info
	// struct, or a composite). Returning a non-nil error aborts the command.
	jsonValue func(results []runner.Result) (any, error)
	// render writes the human / --plain report. Returning a non-nil error aborts.
	render func(results []runner.Result, mode output.OutputMode, elapsed time.Duration) error
}

// runDiagnostic executes a diagnostic spec and applies every cross-cutting
// contract exactly once. New diagnostic commands should be built this way.
func runDiagnostic(cmd *cobra.Command, d diagnostic) error {
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	p := output.NewCommandProgress(d.label, d.timeout, mode, len(d.cols))
	p.Start()
	defer p.Done()

	var results []runner.Result
	for r := range runner.RunAll(cmd.Context(), d.cols) {
		p.Step(r.Name)
		results = append(results, r)
	}
	elapsed := p.Elapsed()

	// Cross-cutting contract: propagate findings to the exit code, every time.
	recordResultSeverity(results)

	if mode == output.ModeJSON {
		v, err := d.jsonValue(results)
		if err != nil {
			return err
		}
		return outputJSON(os.Stdout, v)
	}
	return d.render(results, mode, elapsed)
}

// resultData returns the first collected result whose Data is of type T, or the
// zero value (typically a nil pointer) when none matched.
func resultData[T any](results []runner.Result) T {
	for _, r := range results {
		if v, ok := r.Data.(T); ok {
			return v
		}
	}
	var zero T
	return zero
}

// firstErr returns the first non-nil collector error among results — used by a
// render/jsonValue closure to surface a hard collector failure.
func firstErr(results []runner.Result) error {
	for _, r := range results {
		if r.Err != nil {
			return r.Err
		}
	}
	return nil
}
