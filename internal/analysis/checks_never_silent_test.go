package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// TestChecksNeverSilentlySkip is the regression guard for the false-clean bug
// class: a check function that could not measure/verify something must say so
// (an INFO insight) rather than returning an empty slice indistinguishable
// from "checked and found nothing wrong". Each entry's input reproduces a real
// "could not measure" state; the assertion is that at least one insight is
// emitted and that its message names what could not be verified.
//
// Table-driven and explicit on purpose: a new check with a silent "give up"
// path does not fail this test by construction — it has to be added here,
// which is itself the point (adding a check without adding a row is visible
// in review, not silently uncovered).
func TestChecksNeverSilentlySkip(t *testing.T) {
	tests := []struct {
		name       string
		run        func() []models.Insight
		wantSubstr string // must appear in at least one emitted insight's message
	}{
		{
			name: "checkMemory: cgroup memory unmeasurable in a limited container",
			run: func() []models.Insight {
				ctr := platform.ContainerContext{InContainer: true, MemLimitMB: 2048}
				mem := models.MemoryInfo{UsedPct: 95, TotalGB: 2, FreeGB: 0.1, CgroupMemMeasured: false}
				return checkMemory(mem, defaultThresh, ctr)
			},
			wantSubstr: "could not be read",
		},
		{
			name: "checkOCI: on OCI but every sub-check unreachable",
			run: func() []models.Insight {
				return checkOCI(models.OCIInfo{IsOCI: true})
			},
			wantSubstr: "could not be verified",
		},
		{
			name: "checkSessions: `w` unavailable",
			run: func() []models.Insight {
				return checkSessions(models.SessionsInfo{Checked: false})
			},
			wantSubstr: "could not be enumerated",
		},
		{
			name: "checkContainerGuest: cgroup v1 throttle/OOM signals unread",
			run: func() []models.Insight {
				v := models.ContainerGuestInfo{
					InContainer:      true,
					MemLimitBytes:    1 << 30,
					CPUQuotaCores:    1,
					CgroupV2:         false,
					CgroupV1Measured: false,
				}
				return checkContainerGuest(v)
			},
			wantSubstr: "could not be read on this cgroup v1 host",
		},
		{
			name: "checkPostBoot: prior boot state unmeasurable",
			run: func() []models.Insight {
				return checkPostBoot(models.PostBootInfo{Available: true, State: "unmeasurable"})
			},
			wantSubstr: "forensics unavailable",
		},
		{
			name: "checkElasticsearch: reachable but cluster health unread",
			run: func() []models.Insight {
				return checkElasticsearch(models.ElasticsearchInfo{Detected: true, HealthRead: false})
			},
			wantSubstr: "could not be read",
		},
		{
			name: "checkFirewall: query failed, reason given",
			run: func() []models.Insight {
				return checkFirewall(models.FirewallInfo{Available: false, StatusReason: "nft query failed: permission denied"})
			},
			wantSubstr: "not verified",
		},
		{
			name: "checkAuth: sshd present but auth log unreadable",
			run: func() []models.Insight {
				return checkAuth(models.AuthInfo{Available: true, Checked: false})
			},
			wantSubstr: "could not be read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.run()
			if len(got) == 0 {
				t.Fatalf("silently returned zero insights for an unmeasurable state — this is the false-clean bug")
			}
			found := false
			for _, ins := range got {
				if strings.Contains(ins.Message, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no insight message contains %q, got %+v", tt.wantSubstr, got)
			}
		})
	}
}
