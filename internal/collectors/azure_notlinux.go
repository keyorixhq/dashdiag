//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type AzureCollector struct{}

func NewAzureCollector() *AzureCollector { return &AzureCollector{} }

func (c *AzureCollector) Name() string           { return "Azure" }
func (c *AzureCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *AzureCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.AzureInfo{}, nil
}

// AzureGuestAvailable is always false off Linux — the Azure guest checks read Linux
// DMI/sysfs/procfs paths and Linux-only service state that don't exist elsewhere.
func AzureGuestAvailable() bool { return false }
