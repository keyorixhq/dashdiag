//go:build !linux

package cmd

// shrinkDiskIOSampleGap is a no-op off Linux — collectDiskIO's real 1s
// two-sample sleep only exists on the Linux disk collector path.
func shrinkDiskIOSampleGap() func() {
	return func() {}
}
