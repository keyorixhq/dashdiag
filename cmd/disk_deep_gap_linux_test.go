//go:build linux

package cmd

import (
	"time"

	"github.com/keyorixhq/dashdiag/internal/collectors"
)

// shrinkDiskIOSampleGap shrinks the real two-sample /proc/diskstats gap for
// the duration of a test, returning a restore func. collectDiskIO's 1s sleep
// only exists on Linux (darwin's disk collector never reaches it), so this
// helper is Linux-only; see disk_deep_gap_other_test.go for the no-op stub.
func shrinkDiskIOSampleGap() func() {
	prev := collectors.DiskIOSampleGap
	collectors.DiskIOSampleGap = time.Millisecond
	return func() { collectors.DiskIOSampleGap = prev }
}
