package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckCloudInit(t *testing.T) {
	tests := []struct {
		name      string
		info      models.CloudInitInfo
		wantLevel string // "" means no insight expected
	}{
		{
			name:      "not available",
			info:      models.CloudInitInfo{Available: false, Status: "error"},
			wantLevel: "",
		},
		{
			name:      "done clean",
			info:      models.CloudInitInfo{Available: true, Status: "done", Datasource: "ec2"},
			wantLevel: "",
		},
		{
			name:      "disabled",
			info:      models.CloudInitInfo{Available: true, Status: "disabled"},
			wantLevel: "",
		},
		{
			name:      "error status",
			info:      models.CloudInitInfo{Available: true, Status: "error", Datasource: "ec2"},
			wantLevel: "CRIT",
		},
		{
			name:      "errors present but status not error",
			info:      models.CloudInitInfo{Available: true, Status: "done", Errors: []string{"boom"}},
			wantLevel: "CRIT",
		},
		{
			name:      "degraded done",
			info:      models.CloudInitInfo{Available: true, Status: "done", ExtendedStatus: "degraded done"},
			wantLevel: "WARN",
		},
		{
			name:      "recoverable errors",
			info:      models.CloudInitInfo{Available: true, Status: "done", RecoverableErrors: []string{"WARNING: x"}},
			wantLevel: "WARN",
		},
		{
			name:      "running",
			info:      models.CloudInitInfo{Available: true, Status: "running"},
			wantLevel: "INFO",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCloudInit(tt.info)
			if tt.wantLevel == "" {
				if len(got) != 0 {
					t.Fatalf("expected no insight, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 insight, got %d: %+v", len(got), got)
			}
			if got[0].Level != tt.wantLevel {
				t.Errorf("level = %q, want %q", got[0].Level, tt.wantLevel)
			}
			if got[0].Check != "CloudInit" {
				t.Errorf("check = %q, want CloudInit", got[0].Check)
			}
		})
	}
}

// CRIT must surface up to the first 3 errors plus the inspect/log hints.
func TestCheckCloudInit_ErrorHints(t *testing.T) {
	info := models.CloudInitInfo{
		Available: true, Status: "error",
		Errors: []string{"e1", "e2", "e3", "e4"},
	}
	got := checkCloudInit(info)
	if len(got) != 1 {
		t.Fatalf("expected 1 insight, got %d", len(got))
	}
	// 3 error hints (capped) + 2 trailing inspect/log hints = 5
	if len(got[0].Hints) != 5 {
		t.Errorf("hints len = %d, want 5: %v", len(got[0].Hints), got[0].Hints)
	}
}
