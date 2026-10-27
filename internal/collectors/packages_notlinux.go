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

func NewPackagesCollector() *PackagesCollector     { return &PackagesCollector{} }
func NewPackagesDeepCollector() *PackagesCollector { return &PackagesCollector{} }

func (c *PackagesCollector) Name() string           { return "Packages" }
func (c *PackagesCollector) Timeout() time.Duration { return 30 * time.Second }

func (c *PackagesCollector) Collect(ctx context.Context) (any, error) {
	info := &models.PackagesInfo{Checked: true, PackageManager: "brew"}

	// Homebrew installs to /opt/homebrew on Apple Silicon, /usr/local on Intel.
	// Try absolute paths first since PATH may be restricted (sudo, sh, CI).
	brewPath := ""
	for _, candidate := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if fileExists(candidate) {
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
		// brew failed to run: "0 outdated" is not a result. Checked was optimistically
		// true above; correct it and use the linux collector's query-failed
		// convention so the analysis layer says "could not verify" instead of OK.
		info.Checked = false
		info.Status = "query-failed"
		info.StatusReason = "brew outdated failed to run: " + err.Error()
		return info, nil //nolint:nilerr // brew failure is carried in Status=query-failed/Checked=false, not the error
	}

	for line := range strings.SplitSeq(out, "\n") {
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
