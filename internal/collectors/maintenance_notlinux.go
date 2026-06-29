//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Non-Linux stubs — kdump/tuned/Ksplice/rpm are Linux-only. All gates report
// absent so the collectors never run off Linux.

type KdumpCollector struct{}

func NewKdumpCollector() *KdumpCollector         { return &KdumpCollector{} }
func (c *KdumpCollector) Name() string           { return "Kdump" }
func (c *KdumpCollector) Timeout() time.Duration { return time.Second }
func (c *KdumpCollector) Collect(context.Context) (interface{}, error) {
	return &models.KdumpInfo{}, nil
}
func KdumpAvailable() bool { return false }

type TunedCollector struct{}

func NewTunedCollector() *TunedCollector         { return &TunedCollector{} }
func (c *TunedCollector) Name() string           { return "Tuned" }
func (c *TunedCollector) Timeout() time.Duration { return time.Second }
func (c *TunedCollector) Collect(context.Context) (interface{}, error) {
	return &models.TunedInfo{}, nil
}
func TunedAvailable() bool { return false }

type KernelPatchCollector struct{}

func NewKernelPatchCollector() *KernelPatchCollector   { return &KernelPatchCollector{} }
func (c *KernelPatchCollector) Name() string           { return "Kernel" }
func (c *KernelPatchCollector) Timeout() time.Duration { return time.Second }
func (c *KernelPatchCollector) Collect(context.Context) (interface{}, error) {
	return &models.KernelPatchInfo{}, nil
}
func KernelPatchAvailable() bool { return false }

type KspliceCollector struct{}

func NewKspliceCollector() *KspliceCollector       { return &KspliceCollector{} }
func (c *KspliceCollector) Name() string           { return "Ksplice" }
func (c *KspliceCollector) Timeout() time.Duration { return time.Second }
func (c *KspliceCollector) Collect(context.Context) (interface{}, error) {
	return &models.KspliceInfo{}, nil
}
func KspliceAvailable() bool { return false }

type ServiceRestartCollector struct{}

func NewServiceRestartCollector() *ServiceRestartCollector { return &ServiceRestartCollector{} }
func (c *ServiceRestartCollector) Name() string            { return "ServiceRestart" }
func (c *ServiceRestartCollector) Timeout() time.Duration  { return time.Second }
func (c *ServiceRestartCollector) Collect(context.Context) (interface{}, error) {
	return &models.ServiceRestartInfo{}, nil
}
func ServiceRestartAvailable() bool { return false }
