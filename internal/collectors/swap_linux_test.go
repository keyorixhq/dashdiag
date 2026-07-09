//go:build linux

package collectors

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

var errBoomSwapTest = errors.New("boom")

// TestSwapCollector_Collect_SwapsAndZram exercises the fixture-source-routed
// portion of Collect: /proc/swaps totals and the zram device glob/mm_stat/
// disksize reads. The two vmstat samples still come through the injectable
// reader (per the existing pattern in swap_test.go), but swapsPath and the
// zram sysfs tree are served from a Bundle so no real filesystem is touched.
func TestSwapCollector_Collect_SwapsAndZram(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1s vmstat sampling in short mode")
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/swaps", []byte(
			"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"+
				"/dev/zram0\t\t\t\tpartition\t2097152\t\t524288\t\t100\n"))
		b.PutGlob("/sys/block/zram*", []string{"/sys/block/zram0"})
		b.PutFile("/sys/block/zram0/disksize", []byte("2147483648\n"))                                     // 2 GiB bytes
		b.PutFile("/sys/block/zram0/mm_stat", []byte("536870912 200000 210000 2147483648 210000 0 0 0\n")) // orig 512MiB
	})

	callCount := 0
	c := &SwapCollector{
		ContainerCtx: platform.ContainerContext{},
		swapsPath:    "/proc/swaps",
		readers: swapReaders{
			vmstatOpen: func() (io.ReadCloser, error) {
				callCount++
				if callCount == 1 {
					return io.NopCloser(strings.NewReader("pswpin 100\npswpout 50\n")), nil
				}
				return io.NopCloser(strings.NewReader("pswpin 100\npswpout 50\n")), nil
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := result.(*models.SwapInfo)
	if !ok {
		t.Fatalf("unexpected type %T", result)
	}

	// /proc/swaps: 2097152 kB total, 524288 kB used -> GB and pct.
	if info.TotalGB < 1.99 || info.TotalGB > 2.01 {
		t.Errorf("TotalGB = %v, want ~2.0", info.TotalGB)
	}
	if info.UsedPct < 24.9 || info.UsedPct > 25.1 {
		t.Errorf("UsedPct = %v, want ~25%%", info.UsedPct)
	}
	// zram: 1 device, orig_data_size 512MiB / disksize 2GiB = 25%.
	if info.ZramDevices != 1 {
		t.Errorf("ZramDevices = %d, want 1", info.ZramDevices)
	}
	if info.ZramUsedPct < 24.9 || info.ZramUsedPct > 25.1 {
		t.Errorf("ZramUsedPct = %v, want ~25%%", info.ZramUsedPct)
	}
	// no swap activity between the two identical samples.
	if info.PagesInPerSec != 0 || info.PagesOutPerSec != 0 {
		t.Errorf("PagesInPerSec/PagesOutPerSec = %v/%v, want 0/0", info.PagesInPerSec, info.PagesOutPerSec)
	}
}

// TestSwapCollector_Collect_NoSwapsFile guards the graceful-degrade branch:
// /proc/swaps itself fails to open -> TotalGB/UsedGB/UsedPct simply stay zero
// rather than erroring the whole collector.
func TestSwapCollector_Collect_NoSwapsFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1s vmstat sampling in short mode")
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/block/zram*", nil)
		// /proc/swaps intentionally not seeded -> openFile returns an error.
	})

	c := &SwapCollector{
		ContainerCtx: platform.ContainerContext{},
		swapsPath:    "/proc/swaps",
		readers: swapReaders{
			vmstatOpen: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("pswpin 0\npswpout 0\n")), nil
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := result.(*models.SwapInfo)
	if !ok {
		t.Fatalf("unexpected type %T", result)
	}
	if info.TotalGB != 0 || info.UsedGB != 0 || info.UsedPct != 0 {
		t.Errorf("expected zero swap totals when /proc/swaps is unreadable, got %+v", info)
	}
	if info.ZramDevices != 0 {
		t.Errorf("ZramDevices = %d, want 0", info.ZramDevices)
	}
}

// TestSwapCollector_Collect_VmstatOpenError guards the hard-failure path: the
// FIRST vmstatOpen call errors -> Collect must return an error, not a nil
// SwapInfo.
func TestSwapCollector_Collect_VmstatOpenError(t *testing.T) {
	c := &SwapCollector{
		ContainerCtx: platform.ContainerContext{},
		swapsPath:    "/proc/swaps",
		readers: swapReaders{
			vmstatOpen: func() (io.ReadCloser, error) {
				return nil, errBoomSwapTest
			},
		},
	}
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error when vmstatOpen fails, got nil")
	}
}
