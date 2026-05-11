//go:build !linux

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PackagesCollector checks for outdated Homebrew packages on macOS.
// brew outdated is an acceptable wrapper — no kernel interface for package state.
type PackagesCollector struct{}

func NewPackagesCollector() *PackagesCollector { return &PackagesCollector{} }

func (c *PackagesCollector) Name() string           { return "Packages" }
func (c *PackagesCollector) Timeout() time.Duration { return 30 * time.Second }

func (c *PackagesCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.PackagesInfo{PackageManager: "brew"}

	out, err := runCmd(ctx, "brew", "outdated", "--quiet")
	if err != nil {
		// brew not installed — not an error
		return &models.PackagesInfo{PackageManager: "none"}, nil
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
