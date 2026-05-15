package collectors

import (
	"context"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

type ClockCollector struct{}

func NewClockCollector() *ClockCollector { return &ClockCollector{} }

func (c *ClockCollector) Name() string           { return "Clock" }
func (c *ClockCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *ClockCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ClockInfo{}
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx, info)
	}
	return c.collectLinux(info)
}

func (c *ClockCollector) collectDarwin(ctx context.Context, info *models.ClockInfo) (interface{}, error) {
	// timed is the macOS clock synchronisation daemon. If it's running, the clock is synced.
	// systemsetup -getusingnetworktime requires sudo on macOS Ventura+ and is unreliable.
	// pgrep is macOS-standard and always present — acceptable macOS-only wrapper.
	info.OffsetMs = -1
	if _, err := runCmd(ctx, "pgrep", "timed"); err == nil {
		info.Synced = true
		info.Source = "timed"
	} else {
		info.Synced = false
		info.Source = "unavailable"
	}
	return info, nil
}

func (c *ClockCollector) collectLinux(info *models.ClockInfo) (interface{}, error) {
	if platform.DetectContainerContext().InContainer {
		info.Synced = true
		info.Source = "host"
		info.OffsetMs = -1
		return info, nil
	}

	// Read NTP sync state directly from the kernel via adjtimex(2).
	// This works with all NTP daemons (chrony, systemd-timesyncd, ntpd)
	// because they all drive the kernel clock through this syscall.
	// No external tools, no locale issues, no parsing.
	info.Synced, info.OffsetMs, info.Source = adjtimexSync()

	// Detect RTC in local timezone — causes kernel to report unsync even when
	// NTP is working (Linux Mint, dual-boot with Windows default configuration).
	if b, err := os.ReadFile("/etc/adjtime"); err == nil { // #nosec G304
		info.RTCInLocalTZ = strings.Contains(string(b), "LOCAL")
	}
	return info, nil
}
