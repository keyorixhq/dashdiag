package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckPackages_DBBlockedWarns(t *testing.T) {
	// A blocked package DB must WARN with the reason — even though the update count is
	// a clean zero (the false-OK: "patched" but cannot patch).
	pkg := models.PackagesInfo{
		Checked: true, PackageManager: "apt", SecurityUpdates: 0,
		DBHealthChecked: true, DBUpdatesBlocked: true,
		DBBlockReason: "dpkg is in an interrupted state (packages left half-configured)",
		DBBlockFix:    "sudo dpkg --configure -a",
	}
	got := checkPackages(pkg)
	if !hasInsightMsg(got, "WARN", "silently blocked") {
		t.Fatalf("blocked DB should WARN, got %+v", got)
	}
	if !hasInsightMsg(got, "WARN", "interrupted state") {
		t.Errorf("WARN should carry the reason, got %+v", got)
	}
	// The fix + the "count can't be trusted" caveat must reach the hints.
	var hints []string
	for _, i := range got {
		if strings.Contains(i.Message, "silently blocked") {
			hints = i.Hints
		}
	}
	joined := strings.Join(hints, " | ")
	if !strings.Contains(joined, "dpkg --configure -a") || !strings.Contains(joined, "cannot be trusted") {
		t.Errorf("hints missing fix or trust caveat: %q", joined)
	}
}

func TestCheckPackages_DBHealthyNoBlock(t *testing.T) {
	pkg := models.PackagesInfo{
		Checked: true, PackageManager: "apt", SecurityUpdates: 0,
		DBHealthChecked: true, DBUpdatesBlocked: false,
	}
	for _, i := range checkPackages(pkg) {
		if strings.Contains(i.Message, "silently blocked") {
			t.Errorf("a healthy DB must not emit a block WARN: %q", i.Message)
		}
	}
}
