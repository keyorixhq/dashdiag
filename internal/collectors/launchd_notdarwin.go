//go:build !darwin

package collectors

import (
	"context"
	"time"
)

type LaunchdCollector struct{}

func NewLaunchdCollector() *LaunchdCollector       { return &LaunchdCollector{} }
func (c *LaunchdCollector) Name() string           { return "Launchd" }
func (c *LaunchdCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *LaunchdCollector) Collect(_ context.Context) (interface{}, error) {
	return nil, nil // Launchd is macOS-only — skip on Linux/other
}
