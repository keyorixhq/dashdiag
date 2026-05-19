//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ServicesDeepCollector is a no-op on non-Linux platforms.
// systemd does not exist on macOS or Windows.
type ServicesDeepCollector struct{}

func NewServicesDeepCollector() *ServicesDeepCollector { return &ServicesDeepCollector{} }

func (c *ServicesDeepCollector) Name() string           { return "ServicesDeep" }
func (c *ServicesDeepCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *ServicesDeepCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.ServicesDeepInfo{JournalHealthy: true}, nil
}
