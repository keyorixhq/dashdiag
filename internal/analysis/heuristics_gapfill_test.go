package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests filling coverage gaps in exported wrapper functions and
// small pure helpers across the analysis package — each wrapper below is a thin
// pass-through over an already-tested check* function, so these tests exercise
// the wrapper itself (the part previously uncovered) rather than re-testing the
// underlying heuristic logic.

func TestAWSInsights_Wrapper(t *testing.T) {
	t.Parallel()
	// Not EC2 → nil.
	if got := AWSInsights(models.AWSInfo{IsEC2: false}); got != nil {
		t.Errorf("non-EC2 host must produce no AWS insights, got %+v", got)
	}
	// EC2 → delegates to checkAWS (same result).
	a := models.AWSInfo{IsEC2: true, InstanceType: "t3.micro"}
	got := AWSInsights(a)
	want := checkAWS(a)
	if len(got) != len(want) {
		t.Errorf("AWSInsights must equal checkAWS output: got %d insights, want %d", len(got), len(want))
	}
}

func TestAzureInsights_Wrapper(t *testing.T) {
	t.Parallel()
	if got := AzureInsights(models.AzureInfo{IsAzure: false}); got != nil {
		t.Errorf("non-Azure host must produce no Azure insights, got %+v", got)
	}
	a := models.AzureInfo{IsAzure: true}
	got := AzureInsights(a)
	want := checkAzure(a)
	if len(got) != len(want) {
		t.Errorf("AzureInsights must equal checkAzure output: got %d insights, want %d", len(got), len(want))
	}
}

func TestGCPInsights_Wrapper(t *testing.T) {
	t.Parallel()
	if got := GCPInsights(models.GCPInfo{IsGCP: false}); got != nil {
		t.Errorf("non-GCP host must produce no GCP insights, got %+v", got)
	}
	g := models.GCPInfo{IsGCP: true}
	got := GCPInsights(g)
	want := checkGCP(g)
	if len(got) != len(want) {
		t.Errorf("GCPInsights must equal checkGCP output: got %d insights, want %d", len(got), len(want))
	}
}

func TestOCIInsights_Wrapper(t *testing.T) {
	t.Parallel()
	if got := OCIInsights(models.OCIInfo{IsOCI: false}); got != nil {
		t.Errorf("non-OCI host must produce no OCI insights, got %+v", got)
	}
	o := models.OCIInfo{IsOCI: true}
	got := OCIInsights(o)
	want := checkOCI(o)
	if len(got) != len(want) {
		t.Errorf("OCIInsights must equal checkOCI output: got %d insights, want %d", len(got), len(want))
	}
}

func TestVMwareInsights_Wrapper(t *testing.T) {
	t.Parallel()
	if got := VMwareInsights(models.VMwareInfo{IsGuest: false}); got != nil {
		t.Errorf("non-VMware guest must produce no VMware insights, got %+v", got)
	}
	// IsGuest → runs through AdaptHostHints(checkVMware(...)); just verify it
	// returns something non-nil (the all-clean recognition line at minimum).
	v := models.VMwareInfo{IsGuest: true, ToolsInstalled: true, ToolsRunning: true}
	got := VMwareInsights(v)
	if len(got) == 0 {
		t.Errorf("VMware guest must produce at least the recognition insight, got none")
	}
}

func TestContainerGuestInsights_Wrapper(t *testing.T) {
	t.Parallel()
	if got := ContainerGuestInsights(models.ContainerGuestInfo{InContainer: false}); got != nil {
		t.Errorf("non-container host must produce no container guest insights, got %+v", got)
	}
	v := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, MemLimitBytes: 256 << 20, CPUQuotaCores: 1}
	got := ContainerGuestInsights(v)
	want := AdaptHostHints(checkContainerGuest(v))
	if len(got) != len(want) {
		t.Errorf("ContainerGuestInsights must equal AdaptHostHints(checkContainerGuest(...)): got %d, want %d", len(got), len(want))
	}
}

// containerHumanBytes renders byte counts compactly across unit boundaries, and
// "unset" for zero/negative (no limit configured).
func TestContainerHumanBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   int64
		want string
	}{
		{"zero is unset", 0, "unset"},
		{"negative is unset", -1, "unset"},
		{"bytes", 512, "512 B"},
		{"kilobytes", 4 * 1024, "4 KB"},
		{"megabytes", 256 * 1024 * 1024, "256 MB"},
		{"gigabytes", int64(2 * 1024 * 1024 * 1024), "2.0 GB"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := containerHumanBytes(tt.in); got != tt.want {
				t.Errorf("containerHumanBytes(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// checkServices classifies each probed service result independently: CRIT on a
// bad HTTP status, WARN when unreachable (with the raw error appended when
// present), and silence when reachable and healthy.
func TestCheckServices(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		result    models.ServiceResult
		wantLevel string
		wantMsg   string
	}{
		{
			name:      "crit http status",
			result:    models.ServiceResult{Name: "api", Host: "localhost", Port: 8080, Protocol: "http", Status: "CRIT", StatusCode: 503},
			wantLevel: "CRIT",
			wantMsg:   "returned HTTP 503",
		},
		{
			name:      "unreachable with error",
			result:    models.ServiceResult{Name: "db", Host: "localhost", Port: 5432, Protocol: "tcp", Reachable: false, Error: "connection refused"},
			wantLevel: "WARN",
			wantMsg:   "unreachable: connection refused",
		},
		{
			name:      "unreachable without error",
			result:    models.ServiceResult{Name: "cache", Host: "localhost", Port: 6379, Protocol: "tcp", Reachable: false},
			wantLevel: "WARN",
			wantMsg:   "unreachable",
		},
		{
			name:      "healthy reachable",
			result:    models.ServiceResult{Name: "ok-svc", Host: "localhost", Port: 80, Protocol: "http", Reachable: true, Status: "OK"},
			wantLevel: "",
			wantMsg:   "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := checkServices(models.ServicesInfo{Results: []models.ServiceResult{tt.result}})
			if tt.wantLevel == "" {
				if len(out) != 0 {
					t.Errorf("healthy reachable service must produce no insight, got %+v", out)
				}
				return
			}
			if !hasInsightMsg(out, tt.wantLevel, tt.wantMsg) {
				t.Errorf("expected %s insight containing %q, got %+v", tt.wantLevel, tt.wantMsg, out)
			}
		})
	}
}

func TestCheckServices_Multiple(t *testing.T) {
	t.Parallel()
	s := models.ServicesInfo{Results: []models.ServiceResult{
		{Name: "a", Host: "h1", Port: 1, Status: "CRIT", StatusCode: 500},
		{Name: "b", Host: "h2", Port: 2, Reachable: false, Error: "timeout"},
		{Name: "c", Host: "h3", Port: 3, Reachable: true, Status: "OK"},
	}}
	out := checkServices(s)
	if len(out) != 2 {
		t.Fatalf("expected 2 insights (1 CRIT + 1 WARN) from 3 results, got %d: %+v", len(out), out)
	}
}

// SecurityConcernCount counts only WARN/CRIT insights from checkSecurity — INFO
// findings (e.g. recognition lines) must not inflate the concern count.
func TestSecurityConcernCount(t *testing.T) {
	t.Parallel()
	// A hardened baseline should produce zero (or very few) WARN/CRIT concerns.
	hardened := models.SecurityInfo{SSHStrictModes: true, FirewallActive: true}
	hardenedCount := SecurityConcernCount(hardened)
	wantHardened := 0
	for _, ins := range checkSecurity(hardened) {
		if ins.Level == "WARN" || ins.Level == "CRIT" {
			wantHardened++
		}
	}
	if hardenedCount != wantHardened {
		t.Errorf("SecurityConcernCount(hardened) = %d, want %d (recomputed)", hardenedCount, wantHardened)
	}

	// A host with obvious problems must report a higher concern count.
	risky := models.SecurityInfo{
		SSHPermitRoot:   true,
		SSHPasswordAuth: true,
		FirewallActive:  false,
	}
	riskyCount := SecurityConcernCount(risky)
	if riskyCount <= hardenedCount {
		t.Errorf("SecurityConcernCount(risky)=%d must exceed SecurityConcernCount(hardened)=%d", riskyCount, hardenedCount)
	}
}

// ApplyContainerThresholds raises IO await thresholds to the container-appropriate
// floor, but never lowers a threshold that's already higher (e.g. a cloud-EBS
// baseline that's already at or above the container floor stays untouched).
func TestApplyContainerThresholds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		in          Thresholds
		wantWarnMin float64
		wantCritMin float64
	}{
		{
			name:        "bare-metal floor raised to container minimum",
			in:          Thresholds{IOAwaitWarnMsSSD: 1, IOAwaitCritMsSSD: 5},
			wantWarnMin: 5,
			wantCritMin: 20,
		},
		{
			name:        "already at container minimum stays unchanged",
			in:          Thresholds{IOAwaitWarnMsSSD: 5, IOAwaitCritMsSSD: 20},
			wantWarnMin: 5,
			wantCritMin: 20,
		},
		{
			name:        "higher cloud threshold is preserved, not lowered",
			in:          Thresholds{IOAwaitWarnMsSSD: 8, IOAwaitCritMsSSD: 30},
			wantWarnMin: 8,
			wantCritMin: 30,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			th := tt.in
			ApplyContainerThresholds(&th)
			if th.IOAwaitWarnMsSSD != tt.wantWarnMin {
				t.Errorf("IOAwaitWarnMsSSD = %v, want %v", th.IOAwaitWarnMsSSD, tt.wantWarnMin)
			}
			if th.IOAwaitCritMsSSD != tt.wantCritMin {
				t.Errorf("IOAwaitCritMsSSD = %v, want %v", th.IOAwaitCritMsSSD, tt.wantCritMin)
			}
		})
	}
}
