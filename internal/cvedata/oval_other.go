//go:build !linux

package cvedata

import (
	"context"
	"fmt"
)

func QueryInstalledRPM(_ context.Context) ([]InstalledPackage, error) {
	return nil, fmt.Errorf("rpm queries only supported on Linux")
}

func IsVulnerable(_, _ string) bool { return false }

func CheckCVEFromOVAL(_ context.Context, _, _ string) (*OVALResult, error) {
	return nil, fmt.Errorf("OVAL checks only supported on Linux")
}
