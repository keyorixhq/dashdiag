package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A networkd config file networkd can't read (wrong perms) is silently ignored →
// no network, no error. Must WARN and name the file + the chmod fix.
func TestCheckNetworkdConfigWarnsOnUnreadable(t *testing.T) {
	info := models.NetworkdConfigInfo{
		Detected:   true,
		TotalFiles: 2,
		UnreadableFiles: []models.NetworkdConfigFile{
			{Path: "/etc/systemd/network/10-eth0.network", Mode: "0600"},
		},
	}
	got := checkNetworkdConfig(info)
	if len(got) != 1 {
		t.Fatalf("want 1 insight, got %d", len(got))
	}
	if got[0].Level != "WARN" {
		t.Errorf("level = %q, want WARN", got[0].Level)
	}
	if got[0].Check != "Networkd" {
		t.Errorf("check = %q, want Networkd", got[0].Check)
	}
	joined := got[0].Message + " " + strings.Join(got[0].Hints, " ")
	if !strings.Contains(joined, "10-eth0.network") || !strings.Contains(joined, "chmod 644") {
		t.Errorf("insight should name the offending file + chmod fix: %q / %v", got[0].Message, got[0].Hints)
	}
}

// Healthy host (all files readable) and non-networkd host (Detected=false) stay
// quiet — no false alarm.
func TestCheckNetworkdConfigQuietWhenClean(t *testing.T) {
	if got := checkNetworkdConfig(models.NetworkdConfigInfo{Detected: true, TotalFiles: 3}); len(got) != 0 {
		t.Errorf("clean host must be quiet, got %+v", got)
	}
	if got := checkNetworkdConfig(models.NetworkdConfigInfo{Detected: false}); len(got) != 0 {
		t.Errorf("non-networkd host must be quiet, got %+v", got)
	}
}
