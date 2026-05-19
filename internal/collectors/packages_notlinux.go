//go:build !linux

package collectors

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PackagesCollector checks for outdated Homebrew packages on macOS.
// brew outdated is an acceptable wrapper — no kernel interface for package state.
type PackagesCollector struct{}

func NewPackagesCollector() *PackagesCollector     { return &PackagesCollector{} }
func NewPackagesDeepCollector() *PackagesCollector { return &PackagesCollector{} }

func (c *PackagesCollector) Name() string           { return "Packages" }
func (c *PackagesCollector) Timeout() time.Duration { return 30 * time.Second }

func (c *PackagesCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.PackagesInfo{Checked: true, PackageManager: "brew"}

	// Homebrew installs to /opt/homebrew on Apple Silicon, /usr/local on Intel.
	// Try absolute paths first since PATH may be restricted (sudo, sh, CI).
	brewPath := ""
	for _, candidate := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if _, err := os.Stat(candidate); err == nil {
			brewPath = candidate
			break
		}
	}
	if brewPath == "" {
		// fallback: try PATH lookup
		if out, err := runCmd(ctx, "which", "brew"); err == nil {
			brewPath = strings.TrimSpace(out)
		}
	}
	if brewPath == "" {
		return &models.PackagesInfo{PackageManager: "none"}, nil
	}

	out, err := runCmd(ctx, brewPath, "outdated", "--quiet")
	if err != nil {
		// brew failed to run
		return info, nil
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		info.SecurityUpdates++
		info.Updates = append(info.Updates, models.PackageUpdate{
			Name:     line,
			Severity: "Unknown",
		})
	}
	return info, nil
}
