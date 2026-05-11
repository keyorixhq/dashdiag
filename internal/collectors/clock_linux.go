//go:build linux

package collectors

import "syscall"

// adjtimexSync reads NTP sync state and offset directly from the kernel via
// adjtimex(2). This works with all NTP implementations (chrony, systemd-timesyncd,
// ntpd) because they all drive the kernel clock through this syscall.
//
// Return values:
//   - synced: true if the kernel considers the clock synchronized
//   - offsetMs: current time offset in milliseconds (-1 if unavailable)
//   - source: human-readable source label
func adjtimexSync() (synced bool, offsetMs float64, source string) {
	const (
		timeError = 5      // kernel: clock not synchronized
		staUnsync = 0x0040 // STA_UNSYNC: explicit unsync flag in tx.Status
		staNano   = 0x2000 // STA_NANO: offset field is in nanoseconds (else microseconds)
	)

	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return false, -1, "unavailable"
	}

	synced = state != timeError && (tx.Status&staUnsync) == 0

	if tx.Status&staNano != 0 {
		offsetMs = float64(tx.Offset) / 1e6 // nanoseconds → milliseconds
	} else {
		offsetMs = float64(tx.Offset) / 1e3 // microseconds → milliseconds
	}

	return synced, offsetMs, "adjtimex"
}
