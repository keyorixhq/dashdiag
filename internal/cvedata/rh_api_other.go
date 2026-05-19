//go:build !linux

package cvedata

import (
	"context"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// EnrichFromRHAPI is a no-op on non-Linux platforms.
func EnrichFromRHAPI(_ context.Context, _ string, _ *models.CVEResult) {}
