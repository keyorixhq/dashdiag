package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// DD-COLLECTOR-GAPS-1 High #5: each Logs sub-path whose read failed is named in
// one Unverified INFO; a clean read stays silent.
func TestCheckLogs_SubpathReadFailuresAreUnverified(t *testing.T) {
	t.Parallel()
	cases := map[string]models.LogsInfo{
		"crash loops":           {Available: true, CrashLoopsUnverified: true},
		"crash/core dump files": {Available: true, CrashFilesUnreadable: true},
		"journal size":          {Available: true, JournalSizeUnreadable: true},
		"journal corruption":    {Available: true, JournalCorruptUnverified: true},
	}
	for want, in := range cases {
		got := checkLogs(in, defaultThresh)
		found := false
		for _, ins := range got {
			if ins.Unverified && ins.Level == "INFO" && strings.Contains(ins.Message, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no Unverified INFO naming it in %+v", want, got)
		}
	}
	for _, ins := range checkLogs(models.LogsInfo{Available: true}, defaultThresh) {
		if strings.Contains(ins.Message, "could not verify") {
			t.Errorf("clean read produced a disclosure: %+v", ins)
		}
	}
}
