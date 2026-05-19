//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type ProcCollector struct{ PID int }

func NewProcCollector(pid int) *ProcCollector { return &ProcCollector{PID: pid} }

func (c *ProcCollector) Name() string           { return "Proc" }
func (c *ProcCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *ProcCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.ProcInfo{}, nil
}
