//go:build linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HAProxyAvailable reports whether an haproxy process is running.
func HAProxyAvailable() bool {
	running, _ := procCommRunning("haproxy")
	return running
}

type HAProxyCollector struct{}

func NewHAProxyCollector() *HAProxyCollector { return &HAProxyCollector{} }

func (c *HAProxyCollector) Name() string           { return "HAProxy" }
func (c *HAProxyCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *HAProxyCollector) Collect(ctx context.Context) (interface{}, error) {
	if !HAProxyAvailable() {
		return &models.HAProxyInfo{Detected: false}, nil
	}
	info := &models.HAProxyInfo{Detected: true}
	info.Version = webVersion(ctx, [][]string{{"haproxy", "-v"}}, "version ")
	ran, valid, errLine := webConfigTest(ctx, [][]string{
		{"haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"},
	})
	info.ConfigTested = ran
	info.ConfigValid = valid
	info.ConfigError = errLine
	return info, nil
}
