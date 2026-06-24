package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCountDiskIssuesSMARTWearAndErrors verifies the disk summary counts a drive
// with NVMe media errors or high wear even when SMART overall still reports
// PASSED — otherwise a dying drive reads "Disk healthy" while `dsd health`
// (checkNVMe) raises CRIT/WARN on the same data.
func TestCountDiskIssuesSMARTWearAndErrors(t *testing.T) {
	cases := []struct {
		name  string
		smart *models.SMARTInfo
		want  int
	}{
		{"healthy drive", &models.SMARTInfo{Healthy: true, PercentUsed: 10}, 0},
		{"SMART failed", &models.SMARTInfo{Healthy: false}, 1},
		{"passed but media errors", &models.SMARTInfo{Healthy: true, MediaErrors: 3}, 1},
		{"passed but 90% worn", &models.SMARTInfo{Healthy: true, PercentUsed: 90}, 1},
		{"passed, 89% worn — under threshold", &models.SMARTInfo{Healthy: true, PercentUsed: 89}, 0},
		// Unreadable SMART (smartctl/nvme-cli absent, EBS/virtual disk): Error is set and
		// Healthy defaults to false. That is "couldn't measure", not a fault — it must NOT
		// count, or the summary raises a false WARN where dsd health reports INFO.
		{"SMART unreadable — tool absent", &models.SMARTInfo{Error: "smartctl not installed"}, 0},
		{"no SMART struct", nil, 0},
	}
	for _, c := range cases {
		info := &models.DiskInfo{Drives: []models.PhysicalDrive{{SMART: c.smart}}}
		if got := countDiskIssues(info, nil); got != c.want {
			t.Errorf("%s: countDiskIssues = %d, want %d", c.name, got, c.want)
		}
	}
}
