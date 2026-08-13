package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// ECC memory errors must surface in the fast health Memory check (previously
// only `dsd hardware` saw them — a failing DIMM went unseen by routine health).
func TestCheckMemory_ECC(t *testing.T) {
	var noCtr platform.ContainerContext
	cases := []struct {
		name string
		mem  models.MemoryInfo
		want string
	}{
		{"uncorrected ECC -> CRIT", models.MemoryInfo{EDACAvailable: true, UncorrectedErrors: 1}, "CRIT"},
		{"many corrected ECC -> WARN", models.MemoryInfo{EDACAvailable: true, CorrectedErrors: 500}, "WARN"},
		{"few corrected ECC -> none", models.MemoryInfo{EDACAvailable: true, CorrectedErrors: 50}, ""},
		{"EDAC unavailable -> none (gated)", models.MemoryInfo{EDACAvailable: false, UncorrectedErrors: 999}, ""},
		// internal-collectors-11-03: a counter read failure must disclose INFO
		// rather than silently reading as a clean "0 errors".
		{"counters unreadable with zero counts -> INFO, not silent OK",
			models.MemoryInfo{EDACAvailable: true, EDACCountersUnreadable: true}, "INFO"},
		// A real detected error from a controller that DID read successfully must
		// still CRIT even if another controller's read failed — never suppress a
		// genuine signal because of an unrelated partial-read caveat.
		{"real uncorrected error still CRITs even when another controller is unreadable",
			models.MemoryInfo{EDACAvailable: true, UncorrectedErrors: 1, EDACCountersUnreadable: true}, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertLevel(t, checkMemory(tc.mem, defaultThresh, noCtr), tc.want)
		})
	}
}

// memHotplugInsights flags hot-added RAM the guest isn't using: offline memory
// blocks while auto-onlining is disabled. Gated so it never fires on intentional
// balloon/virtio-mem offlining (auto-online irrelevant there) or healthy hosts.
func TestMemHotplugInsights(t *testing.T) {
	// The bug: offline blocks AND auto-online off → WARN naming the amount.
	bug := models.MemoryInfo{MemHotplugChecked: true, OfflineMemoryBlocks: 4, OfflineMemoryMB: 8192, AutoOnlineBlocks: false}
	got := memHotplugInsights(bug)
	if len(got) != 1 || got[0].Level != "WARN" || got[0].Check != "Memory" {
		t.Fatalf("offline+auto-off = %+v, want one WARN on Memory", got)
	}
	for _, want := range []string{"8.0 GB", "auto-onlining is disabled", "hot-added"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("WARN missing %q, got %q", want, got[0].Message)
		}
	}

	// Auto-onlining ON but blocks offline → balloon/virtio-mem territory, NOT a
	// misconfiguration → silent.
	if got := memHotplugInsights(models.MemoryInfo{MemHotplugChecked: true, OfflineMemoryBlocks: 4, AutoOnlineBlocks: true}); got != nil {
		t.Errorf("auto-online on must be silent (intentional offline), got %v", got)
	}
	// No offline blocks → silent even with auto-online off.
	if got := memHotplugInsights(models.MemoryInfo{MemHotplugChecked: true, OfflineMemoryBlocks: 0, AutoOnlineBlocks: false}); got != nil {
		t.Errorf("no offline blocks must be silent, got %v", got)
	}
	// Hotplug sysfs absent → silent.
	if got := memHotplugInsights(models.MemoryInfo{MemHotplugChecked: false, OfflineMemoryBlocks: 4}); got != nil {
		t.Errorf("unchecked must be silent, got %v", got)
	}

	// Block count only (size unknown) → still WARNs, naming blocks not GB.
	noSize := memHotplugInsights(models.MemoryInfo{MemHotplugChecked: true, OfflineMemoryBlocks: 2, OfflineMemoryMB: 0, AutoOnlineBlocks: false})
	if len(noSize) != 1 || !strings.Contains(noSize[0].Message, "2 memory block(s)") {
		t.Errorf("size-unknown = %+v, want WARN naming '2 memory block(s)'", noSize)
	}
}

// eccInsights is shared by the health and hardware paths; the check name varies
// but thresholds/wording must be identical.
func TestECCInsights(t *testing.T) {
	if got := eccInsights(0, 0, "Memory"); got != nil {
		t.Errorf("clean ECC should yield no insights, got %v", got)
	}
	crit := eccInsights(5, 3, "Memory") // uncorrected outranks corrected
	if len(crit) != 1 || crit[0].Level != "CRIT" || crit[0].Check != "Memory" {
		t.Errorf("uncorrected -> %+v, want one CRIT on Memory", crit)
	}
	warn := eccInsights(101, 0, "Hardware")
	if len(warn) != 1 || warn[0].Level != "WARN" || warn[0].Check != "Hardware" {
		t.Errorf("corrected>100 -> %+v, want one WARN on Hardware", warn)
	}
}
