package collectors

import (
	"encoding/json"
	"testing"
)

// Bundles captured before cpuSample gained the "ok" field recorded the sample
// without it. Replaying such a bundle must not read every recorded sample as a
// failed one ("CPU usage sample failed") — that flipped a healthy replayed host
// to "Not fully verified" and was wrong for all 49 captures in the corpus.
func TestCPUSampleDecode_LegacyRecordingWithoutOK(t *testing.T) {
	cases := []struct {
		name string
		json string
		ok   bool
	}{
		// Verbatim from a real capture (debian13-vmware-root-20260629).
		{"legacy recorded sample with data", `{"usage_pct":33.33333333333333,"steal_pct":0,"iowait_pct":2.0202020202020203,"ctx_switch_rate":9224.03046251723,"run_queue":5,"procs_blocked":0}`, true},
		// A legacy FAILED sample was an all-zero struct: still a failure.
		{"legacy all-zero sample", `{"usage_pct":0,"steal_pct":0,"iowait_pct":0,"ctx_switch_rate":0,"run_queue":0,"procs_blocked":0}`, false},
		// New recordings state it explicitly, and an explicit false wins over data.
		{"explicit ok true", `{"usage_pct":1,"run_queue":2,"ok":true}`, true},
		{"explicit ok false", `{"usage_pct":0,"run_queue":0,"ok":false}`, false},
		{"explicit ok false with stray data", `{"usage_pct":5,"run_queue":3,"ok":false}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s cpuSample
			if err := json.Unmarshal([]byte(c.json), &s); err != nil {
				t.Fatal(err)
			}
			if s.OK != c.ok {
				t.Errorf("OK = %v, want %v for %s", s.OK, c.ok, c.json)
			}
		})
	}
}
