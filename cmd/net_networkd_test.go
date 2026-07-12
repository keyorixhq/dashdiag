package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestPrintNetworkdReport_StuckLink: a link stuck in SETUP=configuring must NOT be
// reported as "all links configured" and must be listed (regression: the healthy
// gate only checked UnreadableFiles+FailedLinks, so a stuck link printed the green
// "all links configured" line while dsd health WARNed — a cmd↔health contradiction).
func TestPrintNetworkdReport_StuckLink(t *testing.T) {
	info := &models.NetworkdConfigInfo{
		Detected:   true,
		TotalFiles: 3,
		StuckLinks: []models.NetworkdLink{{Name: "eth1", Setup: "configuring", Operational: "no-carrier"}},
	}
	out := captureStdout(t, func() { printNetworkdReport(info, output.ModePlain) })

	if strings.Contains(out, "all links configured") {
		t.Errorf("a stuck link must not render as 'all links configured':\n%s", out)
	}
	if !strings.Contains(out, "eth1") || !strings.Contains(out, "SETUP=configuring") {
		t.Errorf("the stuck link eth1 must be listed:\n%s", out)
	}
}

// TestPrintNetworkdReport_AllClean: with nothing wrong, the green summary still prints.
func TestPrintNetworkdReport_AllClean(t *testing.T) {
	info := &models.NetworkdConfigInfo{Detected: true, TotalFiles: 2}
	out := captureStdout(t, func() { printNetworkdReport(info, output.ModePlain) })

	if !strings.Contains(out, "all links configured") {
		t.Errorf("a clean host should print the green summary:\n%s", out)
	}
}

// TestPrintNetworkdReport_UnreadableFileAndFailedLink covers the
// UnreadableFiles (plus its "to fix: chmod" hint) and FailedLinks branches,
// neither exercised by the stuck-link/all-clean tests above.
func TestPrintNetworkdReport_UnreadableFileAndFailedLink(t *testing.T) {
	info := &models.NetworkdConfigInfo{
		Detected:        true,
		TotalFiles:      2,
		UnreadableFiles: []models.NetworkdConfigFile{{Path: "/etc/systemd/network/10-eth0.network", Mode: "0600"}},
		FailedLinks:     []models.NetworkdLink{{Name: "eth0", Setup: "failed", Operational: "down"}},
	}
	out := captureStdout(t, func() { printNetworkdReport(info, output.ModePlain) })

	if !strings.Contains(out, "not readable by networkd") || !strings.Contains(out, "0600") {
		t.Errorf("an unreadable config file should be listed with its mode, got:\n%s", out)
	}
	if !strings.Contains(out, "to fix: chmod 644 /etc/systemd/network/10-eth0.network") {
		t.Errorf("the chmod fix hint should name the first unreadable file, got:\n%s", out)
	}
	if !strings.Contains(out, "eth0") || !strings.Contains(out, "SETUP=failed") {
		t.Errorf("a failed link should be listed, got:\n%s", out)
	}
}
