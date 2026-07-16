//go:build darwin

package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// TestCheckMemory_DarwinHints covers the runtime.GOOS == "darwin" branch in
// checkMemory (line 151-153). On macOS the memory hints use vm_stat/top rather
// than free/ps, so the insight must mention "vm_stat" instead of "free".
func TestCheckMemory_DarwinHints(t *testing.T) {
	t.Parallel()
	mem := models.MemoryInfo{
		UsedPct: defaultThresh.RAMCritPct + 1,
		TotalGB: 16,
		FreeGB:  0.5,
	}
	got := checkMemory(mem, defaultThresh, platform.ContainerContext{})
	if len(got) == 0 {
		t.Fatal("expected a memory insight at high usage, got none")
	}
	hintText := strings.Join(got[0].Hints, " | ")
	if !strings.Contains(hintText, "vm_stat") {
		t.Errorf("darwin memory hint must include vm_stat, got %q", hintText)
	}
	if strings.Contains(hintText, "free -h") {
		t.Errorf("darwin memory hint must not use linux 'free -h', got %q", hintText)
	}
}
