package collectors

import (
	"context"
	"encoding/json"
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

// clockState is the live NTP-sync state, serialised through the active source so
// `dsd capture`/`dsd replay` reproduce the CAPTURED host's verdict rather than the
// replaying machine's. Two non-hermetic inputs are folded in here: the container
// short-circuit (DetectContainerContext) and the adjtimex(2) syscall. Without
// routing them through Source, replaying a bare-metal/VM capture inside a
// container — or on a machine whose own clock is synced — silently flipped an
// unsynced clock to "host: synced", masking the captured host's real CRIT.
type clockState struct {
	Synced   bool    `json:"synced"`
	OffsetMs float64 `json:"offset_ms"`
	Source   string  `json:"source"`
}

// liveClockState reads the NTP sync state from the live system. In a container
// the kernel clock is the host's, so we report it as synced from "host". Outside
// a container we read directly from the kernel via adjtimex(2) — this works with
// all NTP daemons (chrony, systemd-timesyncd, ntpd) because they all drive the
// kernel clock through this syscall. No external tools, no locale issues.
func liveClockState() clockState {
	if platform.DetectContainerContext().InContainer {
		return clockState{Synced: true, OffsetMs: -1, Source: "host"}
	}
	synced, offsetMs, source := adjtimexSync()
	return clockState{Synced: synced, OffsetMs: offsetMs, Source: source}
}

func (c *ClockCollector) collectLinux(info *models.ClockInfo) (interface{}, error) {
	// Route the live read through Source so it is recorded by capture and replayed
	// faithfully. On replay of a bundle predating this key, Cached returns
	// ErrNotRecorded and we fall back to a live read (never block a live run).
	var st clockState
	if b, err := activeSource.Cached("clock/state", func() ([]byte, error) {
		return json.Marshal(liveClockState())
	}); err == nil {
		_ = json.Unmarshal(b, &st)
	} else {
		st = liveClockState()
	}
	info.Synced, info.OffsetMs, info.Source = st.Synced, st.OffsetMs, st.Source

	// Detect RTC in local timezone — causes kernel to report unsync even when
	// NTP is working (Linux Mint, dual-boot with Windows default configuration).
	if b, err := readFile("/etc/adjtime"); err == nil { // #nosec G304
		info.RTCInLocalTZ = strings.Contains(string(b), "LOCAL")
	}
	return info, nil
}
