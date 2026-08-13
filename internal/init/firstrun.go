package init_pkg

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/dashdiag/internal/output"
	tui "github.com/keyorixhq/dashdiag/internal/tui"
)

func IsFirstRun() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		// Can't resolve a home directory (HOME unset, no usable passwd entry).
		// Silently falling through to filepath.Join("", ...) would resolve to
		// the relative path "./.dsd/state.json" and make the first-run check
		// depend on whatever directory dsd happens to be invoked from — e.g. a
		// shared/world-writable working directory that may or may not happen
		// to contain a stray .dsd/state.json. Fail closed: without a reliable
		// home directory, never claim this IS a first run (which would trigger
		// interactive wizard logic) purely because CWD state can't be trusted.
		return false
	}
	_, statErr := os.Stat(filepath.Join(home, ".dsd", "state.json"))
	return os.IsNotExist(statErr)
}

func RunWizard(_ output.OutputMode) error {
	profile, ok := DetectServerProfile()
	if ok {
		fmt.Printf("Detected server type: %s\n", profile)
	} else {
		// The process scan itself failed (ReadDir("/proc") error on Linux, or
		// `ps aux` errored/timed out on macOS) — "general" here is a fallback
		// default, not a confirmed detection, and must not be presented as one.
		fmt.Printf("Detected server type: %s (process list unavailable — please verify)\n", profile)
	}
	chosen, err := tui.RunSingleSelect(
		"Confirm server profile (affects default thresholds):",
		[]string{"web", "database", "kubernetes", "proxmox", "general"},
	)
	if err != nil || chosen == "" {
		return nil
	}
	writeProfileConfig(chosen)
	fmt.Printf("✅ Profile saved to ~/.dsd.yaml\n\n")
	return nil
}

func writeProfileConfig(profile string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, ".dsd.yaml")
	content := fmt.Sprintf("# DashDiag configuration\n# Profile: %s\n# Edit thresholds here\nthresholds:\n", profile)
	// O_EXCL: atomically create-if-absent instead of Stat-then-WriteFile.
	// The Stat check had a TOCTOU window, and independent of timing, if
	// ~/.dsd.yaml were a dangling symlink, os.Stat would report "not exist"
	// and a plain os.WriteFile would follow the symlink and create/overwrite
	// its target rather than refusing it. O_EXCL fails atomically on either
	// an existing regular file OR an existing symlink (dangling or not), with
	// no separate check-then-act window.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G304 -- path is ~/.dsd.yaml, not user input
	if err != nil {
		return // already exists (file or symlink) — "only write if absent"
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		fmt.Fprintf(os.Stderr, "dsd: writing %s: %v\n", path, err)
	}
}
