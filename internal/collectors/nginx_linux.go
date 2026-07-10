//go:build linux

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// NginxAvailable reports whether an nginx process is running on this host.
func NginxAvailable() bool {
	running, _ := procCommRunning("nginx")
	return running
}

type NginxCollector struct{}

func NewNginxCollector() *NginxCollector { return &NginxCollector{} }

func (c *NginxCollector) Name() string           { return "Nginx" }
func (c *NginxCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *NginxCollector) Collect(ctx context.Context) (interface{}, error) {
	running, _ := procCommRunning("nginx")
	if !running {
		return &models.NginxInfo{Detected: false}, nil
	}
	info := &models.NginxInfo{Detected: true, MasterRunning: true, Workers: countNginxWorkers()}

	// Version — nginx writes "-v" to stderr.
	if res, err := curSource().Run(ctx, "nginx", "-v"); err == nil {
		info.Version = parseNginxVersion(string(res.Stderr) + string(res.Stdout))
	}

	collectNginxConfigTest(ctx, info)
	return info, nil
}

// collectNginxConfigTest runs `nginx -t` (stderr) and classifies the result.
// nginx keeps serving its last-loaded config, so an invalid on-disk config is a
// latent outage — surfaced here before the next reload. Distinguishes a genuine
// syntax error (ConfigValid=false) from a "couldn't read the config" permission
// failure (ConfigTested=false → reported as INFO, never a false CRIT).
func collectNginxConfigTest(ctx context.Context, info *models.NginxInfo) {
	res, err := curSource().Run(ctx, "nginx", "-t")
	if err != nil {
		info.StatusReason = "nginx -t could not run"
		return
	}
	stderr := string(res.Stderr) + string(res.Stdout)
	if res.ExitCode == 0 {
		info.ConfigTested = true
		info.ConfigValid = true
		return
	}
	// A permission failure reading the config is "couldn't test", not "invalid".
	if strings.Contains(stderr, "Permission denied") || strings.Contains(stderr, "(13:") {
		info.StatusReason = "nginx -t needs root to read the config"
		return
	}
	info.ConfigTested = true
	info.ConfigValid = false
	info.ConfigError = firstNginxError(stderr)
}

// firstNginxError returns the first emerg/error line from nginx -t output.
func firstNginxError(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "[emerg]") || strings.Contains(line, "[error]") {
			return line
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return "config test failed"
}

func parseNginxVersion(out string) string {
	// "nginx version: nginx/1.27.0"
	if i := strings.Index(out, "nginx/"); i >= 0 {
		v := out[i+len("nginx/"):]
		return strings.TrimSpace(strings.SplitN(v, "\n", 2)[0])
	}
	return ""
}

// countNginxWorkers counts running "nginx: worker process" entries via /proc.
// Best-effort: another user's cmdline may be unreadable, so this is reported as
// state, never used to raise a false "no workers" alarm.
func countNginxWorkers() int {
	entries, err := readDirEntries("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cmd, err := readFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if strings.Contains(strings.ReplaceAll(string(cmd), "\x00", " "), "worker process") {
			n++
		}
	}
	return n
}
