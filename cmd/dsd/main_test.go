package main

import (
	"os"
	"testing"
)

// TestMain_VersionFlag exercises main() via the --version short-circuit,
// the one path that returns instead of calling os.Exit (cmd.Execute only
// exits on error or a recorded non-zero severity — see cmd/root.go).
func TestMain_VersionFlag(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"dsd", "--version"}

	main()
}
