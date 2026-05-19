//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type KVMCollector struct{ Deep bool }

func NewKVMCollector() *KVMCollector     { return &KVMCollector{} }
func NewKVMDeepCollector() *KVMCollector { return &KVMCollector{Deep: true} }

func (c *KVMCollector) Name() string           { return "KVM" }
func (c *KVMCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *KVMCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.KVMInfo{}, nil
}

// KVMAvailable returns false on non-Linux platforms.
func KVMAvailable() bool { return false }
