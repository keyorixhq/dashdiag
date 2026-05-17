//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type IPMICollector struct{}

func NewIPMICollector() *IPMICollector          { return &IPMICollector{} }
func (c *IPMICollector) Name() string           { return "IPMI" }
func (c *IPMICollector) Timeout() time.Duration { return 3 * time.Second }

func (c *IPMICollector) Collect(_ context.Context) (interface{}, error) {
	return &models.IPMIInfo{}, nil
}

func IsIPMIPresent() bool { return false }
