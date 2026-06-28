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
