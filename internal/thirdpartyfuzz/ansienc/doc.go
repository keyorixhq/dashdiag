// Package ansienc holds the MC1 third-party fuzz target for
// github.com/charmbracelet/x/ansi — the width / truncate / wrap layer DashDiag
// reaches through lipgloss when it measures and lays out host-derived terminal
// text. The package has no production code of its own; it exists only to host
// the fuzz target in its own directory (one directory per third-party library,
// per the MC1 conventions). See mc1_ansi_width_fuzz_test.go for the invariants.
package ansienc
