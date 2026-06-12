//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FuzzParseMDStat fuzzes the /proc/mdstat parser. mdstat content reflects RAID
// array state; a parser crash on a malformed/truncated mdstat would take down
// the RAID collector. The false-OK risk is "garbled mdstat → no degraded-array
// warning". Invariant: never panic. (Linux-tagged: parseMDStat lives in
// raid_linux.go.)
func FuzzParseMDStat(f *testing.F) {
	seeds := []string{
		"Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n      1000 blocks [2/2] [UU]\n",
		"md0 : active raid1 sda1[0] sdb1[1]\n      1000 blocks [2/1] [U_]\n", // degraded
		"Personalities :\n",
		"",
		"garbage\nlines\nwithout structure",
		"md0 : active raid5 sda[0] sdb[1] sdc[2]\n  [====>....] recovery = 50.0%",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		_ = parseMDStat(strings.NewReader(content))
	})
}

// FuzzParseNVMeSmartLog fuzzes the `nvme smart-log` / smartctl output parser.
// External-tool stdout (THREAT_MODEL_CLI.md §5). Invariant: never panic on
// arbitrary key:value output; the collector must not misread a hostile/garbled
// SMART log into a false-healthy device. (Linux-tagged.)
func FuzzParseNVMeSmartLog(f *testing.F) {
	seeds := []string{
		"critical_warning : 0\ntemperature : 35 C\npercentage_used : 2%\n",
		"temperature : 9001 C\n",
		"critical_warning : 0x4\n",
		"no colon lines here",
		"",
		"temperature :\npercentage_used : abc%\n",
		"key : \x00\x00 : extra",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		var dev models.NVMeDevice
		parseNVMeSmartLog(out, &dev)
	})
}

// FuzzParseLVMRaid fuzzes the LVM-raid lvs output parser. External-tool stdout.
// Invariant: never panic. (Linux-tagged: parseLVMRaid lives in lvm_linux.go.)
func FuzzParseLVMRaid(f *testing.F) {
	seeds := []string{
		"lvraid vg0 raid1 100.00 idle 0.00",
		"lvraid vg0 raid5 100.00 refresh needed 50.00",
		"short line",
		"",
		"a b c d e f g h",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		_ = parseLVMRaid(out)
	})
}
