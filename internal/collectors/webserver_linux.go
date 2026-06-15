//go:build linux

package collectors

import (
	"context"
	"strings"
)

// webConfigTest runs the first runnable config-test command (binary present) and
// reports whether it ran, whether the config is valid (exit 0), and the first
// error line. A permission failure reading the config counts as "didn't run"
// (ran=false) — never a false "invalid". Used by the apache and haproxy
// collectors; reads stderr (where these tools write their results) via the
// source layer so capture/replay reproduces it.
func webConfigTest(ctx context.Context, cmds [][]string) (ran, valid bool, errLine string) {
	for _, c := range cmds {
		if len(c) == 0 {
			continue
		}
		res, err := activeSource.Run(ctx, c[0], c[1:]...)
		if err != nil {
			continue // binary not found / spawn failure — try the next candidate
		}
		out := string(res.Stderr) + string(res.Stdout)
		if res.ExitCode == 0 {
			return true, true, ""
		}
		if strings.Contains(out, "Permission denied") || strings.Contains(out, "(13:") {
			return false, false, "" // couldn't read the config — not a syntax verdict
		}
		return true, false, firstConfigError(out)
	}
	return false, false, ""
}

// firstConfigError returns the most error-like line from config-test output,
// falling back to the first non-empty line.
func firstConfigError(out string) string {
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		low := strings.ToLower(l)
		for _, marker := range []string{"[emerg]", "[alert]", "error", "invalid", "syntax", "failed", "cannot"} {
			if strings.Contains(low, marker) {
				return l
			}
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return "config test failed"
}

// webVersion runs the first runnable version command and extracts the version
// token following marker (e.g. "Apache/", "version ").
func webVersion(ctx context.Context, cmds [][]string, marker string) string {
	for _, c := range cmds {
		if len(c) == 0 {
			continue
		}
		res, err := activeSource.Run(ctx, c[0], c[1:]...)
		if err != nil {
			continue
		}
		out := string(res.Stderr) + string(res.Stdout)
		if i := strings.Index(out, marker); i >= 0 {
			v := strings.TrimSpace(out[i+len(marker):])
			return strings.Fields(v + " ")[0]
		}
	}
	return ""
}
