//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// Non-Linux stubs — kdump/tuned/Ksplice/rpm are Linux-only. All gates report
// absent so the collectors never run off Linux.

type KdumpCollector struct{}

func NewKdumpCollector(platform.ContainerContext) *KdumpCollector { return &KdumpCollector{} }
func (c *KdumpCollector) Name() string                            { return "Kdump" }
func (c *KdumpCollector) Timeout() time.Duration                  { return time.Second }
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

func NewKernelPatchCollector(platform.ContainerContext) *KernelPatchCollector {
	return &KernelPatchCollector{}
}
func (c *KernelPatchCollector) Name() string           { return "Kernel" }
func (c *KernelPatchCollector) Timeout() time.Duration { return time.Second }
func (c *KernelPatchCollector) Collect(context.Context) (interface{}, error) {
	return &models.KernelPatchInfo{}, nil
}
func KernelPatchAvailable() bool { return false }

type KspliceCollector struct{}

func NewKspliceCollector(platform.ContainerContext) *KspliceCollector { return &KspliceCollector{} }
func (c *KspliceCollector) Name() string                              { return "Ksplice" }
func (c *KspliceCollector) Timeout() time.Duration                    { return time.Second }
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

type KernelRetentionCollector struct{}

func NewKernelRetentionCollector(platform.ContainerContext) *KernelRetentionCollector {
	return &KernelRetentionCollector{}
}
func (c *KernelRetentionCollector) Name() string           { return "KernelRetention" }
func (c *KernelRetentionCollector) Timeout() time.Duration { return time.Second }
func (c *KernelRetentionCollector) Collect(context.Context) (interface{}, error) {
	return &models.KernelRetentionInfo{}, nil
}
func KernelRetentionAvailable() bool { return false }

type LivePatchCollector struct{}

func NewLivePatchCollector(platform.ContainerContext) *LivePatchCollector {
	return &LivePatchCollector{}
}
func (c *LivePatchCollector) Name() string           { return "LivePatch" }
func (c *LivePatchCollector) Timeout() time.Duration { return time.Second }
func (c *LivePatchCollector) Collect(context.Context) (interface{}, error) {
	return &models.LivePatchInfo{}, nil
}
func LivePatchAvailable() bool { return false }

type TransactionalCollector struct{}

func NewTransactionalCollector(platform.ContainerContext) *TransactionalCollector {
	return &TransactionalCollector{}
}
func (c *TransactionalCollector) Name() string           { return "Transactional" }
func (c *TransactionalCollector) Timeout() time.Duration { return time.Second }
func (c *TransactionalCollector) Collect(context.Context) (interface{}, error) {
	return &models.TransactionalInfo{}, nil
}
func TransactionalAvailable() bool { return false }
