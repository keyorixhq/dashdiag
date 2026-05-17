//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type SRIOVCollector struct{}

func NewSRIOVCollector() *SRIOVCollector         { return &SRIOVCollector{} }
func (c *SRIOVCollector) Name() string           { return "SRIOV" }
func (c *SRIOVCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *SRIOVCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.SRIOVInfo{}, nil
}

func IsSRIOVPresent() bool { return false }
