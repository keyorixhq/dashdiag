//go:build linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ApacheAvailable reports whether an Apache httpd process is running (httpd on
// RHEL-family, apache2 on Debian-family).
func ApacheAvailable() bool {
	for _, name := range []string{"httpd", "apache2"} {
		if running, _ := procCommRunning(name); running {
			return true
		}
	}
	return false
}

type ApacheCollector struct{}

func NewApacheCollector() *ApacheCollector { return &ApacheCollector{} }

func (c *ApacheCollector) Name() string           { return "Apache" }
func (c *ApacheCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *ApacheCollector) Collect(ctx context.Context) (interface{}, error) {
	if !ApacheAvailable() {
		return &models.ApacheInfo{Detected: false}, nil
	}
	info := &models.ApacheInfo{Detected: true}
	info.Version = webVersion(ctx, [][]string{
		{"apachectl", "-v"}, {"apache2ctl", "-v"}, {"httpd", "-v"},
	}, "Apache/")
	ran, valid, errLine := webConfigTest(ctx, [][]string{
		{"apache2ctl", "configtest"}, // Debian/Ubuntu (handles APACHE_* env)
		{"apachectl", "configtest"},  // RHEL/generic
		{"httpd", "-t"},
		{"apachectl", "-t"},
	})
	info.ConfigTested = ran
	info.ConfigValid = valid
	info.ConfigError = errLine
	return info, nil
}
