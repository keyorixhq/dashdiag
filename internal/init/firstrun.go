package init_pkg

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/dashdiag/internal/output"
	tui "github.com/keyorixhq/dashdiag/internal/tui"
)

func IsFirstRun() bool {
	home, _ := os.UserHomeDir()
	_, err := os.Stat(filepath.Join(home, ".dsd", "state.json"))
	return os.IsNotExist(err)
}

func RunWizard(_ output.OutputMode) error {
	profile := DetectServerProfile()
	fmt.Printf("Detected server type: %s\n", profile)
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
	// Only write if file doesn't exist
	if _, err := os.Stat(path); err == nil {
		return
	}
	content := fmt.Sprintf("# DashDiag configuration\n# Profile: %s\n# Edit thresholds here\nthresholds:\n", profile)
	os.WriteFile(path, []byte(content), 0644)
}
