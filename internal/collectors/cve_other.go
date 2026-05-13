//go:build !linux

package collectors

import (
	"context"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func CheckCVE(_ context.Context, cveID string) *models.CVEResult {
	return &models.CVEResult{
		CVE:          cveID,
		Status:       models.CVEUnknown,
		StatusReason: "CVE checks are only supported on Linux",
	}
}

func ScanAllCVEs(_ context.Context) *models.CVEAllResult {
	return &models.CVEAllResult{
		StatusReason: "CVE scanning is only supported on Linux",
	}
}
