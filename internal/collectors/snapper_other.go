//go:build !linux

package collectors

import (
	"context"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// CollectSnapper is not supported on non-Linux platforms.
func CollectSnapper(_ context.Context) (*models.SnapperInfo, error) {
	return &models.SnapperInfo{}, nil
}
