package collectors

import (
	"context"
	"runtime"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestClockCollector_ReturnsResult(t *testing.T) {
	t.Parallel()
	c := NewClockCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if _, ok := result.(*models.ClockInfo); !ok {
		t.Fatalf("expected *models.ClockInfo, got %T", result)
	}
}

func TestAdjtimexSync_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("adjtimex only on Linux")
	}
	t.Parallel()
	synced, offsetMs, source := adjtimexSync()
	if source == "" {
		t.Error("source must not be empty")
	}
	// On a healthy system with NTP, synced should be true.
	// We don't assert synced==true because CI hosts may not have NTP.
	t.Logf("adjtimex: synced=%v offsetMs=%.3f source=%s", synced, offsetMs, source)
}
