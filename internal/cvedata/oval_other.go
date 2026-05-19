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

// OVALCVSSResult stub for non-Linux.
type OVALCVSSResult struct {
	CVEID      string
	CVSS3      float64
	Severity   string
	State      string
	Components []string
	Installed  []string
}

// RHELCVERecord stub for non-Linux.
type RHELCVERecord struct {
	CVEID       string
	CVSS3       float64
	CVSS3Vector string
	Severity    string
	Components  []string
	State       string
}

func ParseRHELOVAL(_ string) (map[string]RHELCVERecord, error) {
	return nil, fmt.Errorf("RHEL OVAL parsing only supported on Linux")
}

func ParseUbuntuOVAL(_ string) (map[string]RHELCVERecord, error) {
	return nil, fmt.Errorf("Ubuntu OVAL parsing only supported on Linux")
}

func ScanOVALPackages(_ context.Context, _ string) ([]OVALCVSSResult, error) {
	return nil, fmt.Errorf("OVAL package scan only supported on Linux")
}

func ScanUbuntuOVALPackages(_ context.Context, _ string) ([]OVALCVSSResult, error) {
	return nil, fmt.Errorf("Ubuntu OVAL package scan only supported on Linux")
}

func QueryInstalledDPKG(_ context.Context) ([]InstalledPackage, error) {
	return nil, fmt.Errorf("dpkg queries only supported on Linux")
}
