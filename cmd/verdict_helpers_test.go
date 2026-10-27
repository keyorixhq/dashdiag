package cmd

import "github.com/keyorixhq/dashdiag/internal/render"

// cleanVerdict is the verdict of a run in which every collector ran and found
// nothing wrong — what the per-subcommand renderers are handed on a healthy
// host. Tests that exercise the renderer's own per-section concern logic pass
// it so the verdict does not interfere; the verdict-driven cases live in
// subcommand_verdict_test.go.
func cleanVerdict() render.VerdictInfo { return render.Verdict(nil, nil) }
