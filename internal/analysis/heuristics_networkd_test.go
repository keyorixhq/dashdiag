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

// A managed link networkd failed to configure (SETUP=failed) → WARN naming the
// link. SETUP=failed is the unambiguous "config did not apply" signal.
func TestCheckNetworkdConfigWarnsOnFailedLink(t *testing.T) {
	info := models.NetworkdConfigInfo{
		Detected:    true,
		TotalFiles:  2,
		FailedLinks: []models.NetworkdLink{{Name: "eth1", Setup: "failed", Operational: "no-carrier"}},
	}
	got := checkNetworkdConfig(info)
	if len(got) != 1 || got[0].Level != "WARN" {
		t.Fatalf("want 1 WARN, got %+v", got)
	}
	joined := got[0].Message + " " + strings.Join(got[0].Hints, " ")
	if !strings.Contains(joined, "eth1") || !strings.Contains(got[0].Message, "SETUP=failed") {
		t.Errorf("insight should name the failed link + reason: %q / %v", got[0].Message, got[0].Hints)
	}
}

// TestCheckNetworkdConfigUnverifiedOnDirUnreadable is the shared-glob-fix
// regression test's analysis-layer half: a permission-denied config
// directory (ConfigDirUnreadable, set by globChecked in the collector) must
// surface as an unverified disclosure — TotalFiles==0 here looks IDENTICAL
// to a genuinely empty, fully-readable directory (TestCheckNetworkdConfigQuietWhenClean
// below), so ConfigDirUnreadable is the only signal distinguishing "audited,
// clean" from "could not audit at all".
func TestCheckNetworkdConfigUnverifiedOnDirUnreadable(t *testing.T) {
	info := models.NetworkdConfigInfo{Detected: true, ConfigDirUnreadable: true}
	got := checkNetworkdConfig(info)
	if len(got) != 1 {
		t.Fatalf("want 1 insight, got %d: %+v", len(got), got)
	}
	if got[0].Level != "INFO" {
		t.Errorf("level = %q, want INFO", got[0].Level)
	}
	if !got[0].Unverified {
		t.Error("expected Unverified=true — this is a couldn't-audit caveat, not a genuine clean finding")
	}
}

// Healthy host (all files readable, all links configured) and non-networkd host
// (Detected=false) stay quiet — no false alarm.
func TestCheckNetworkdConfigQuietWhenClean(t *testing.T) {
	if got := checkNetworkdConfig(models.NetworkdConfigInfo{Detected: true, TotalFiles: 3}); len(got) != 0 {
		t.Errorf("clean host must be quiet, got %+v", got)
	}
	if got := checkNetworkdConfig(models.NetworkdConfigInfo{Detected: false}); len(got) != 0 {
		t.Errorf("non-networkd host must be quiet, got %+v", got)
	}
}

// A link stuck in SETUP=configuring long after boot → WARN naming it.
func TestCheckNetworkdConfigWarnsOnStuckLink(t *testing.T) {
	info := models.NetworkdConfigInfo{
		Detected:   true,
		StuckLinks: []models.NetworkdLink{{Name: "eth1", Setup: "configuring", Operational: "no-carrier"}},
	}
	got := checkNetworkdConfig(info)
	if len(got) != 1 || got[0].Level != "WARN" {
		t.Fatalf("want 1 WARN for stuck link, got %+v", got)
	}
	joined := got[0].Message + " " + strings.Join(got[0].Hints, " ")
	if !strings.Contains(joined, "eth1") || !strings.Contains(got[0].Message, "stuck") {
		t.Errorf("insight should name the stuck link: %q / %v", got[0].Message, got[0].Hints)
	}
}
