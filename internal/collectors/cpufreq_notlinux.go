//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type CPUFreqCollector struct{}

func NewCPUFreqCollector() *CPUFreqCollector       { return &CPUFreqCollector{} }
func (c *CPUFreqCollector) Name() string           { return "CPUFreq" }
func (c *CPUFreqCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *CPUFreqCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.CPUFreqInfo{}, nil
}

func IsCPUFreqAvailable() bool { return false }
