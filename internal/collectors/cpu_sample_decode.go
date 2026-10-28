package collectors

import "encoding/json"

// UnmarshalJSON keeps bundles recorded before the "ok" field existed replaying
// as the successful samples they were. Without it every older recording decodes
// OK=false and replays as "CPU usage sample failed". A recording without "ok"
// is a success unless it is the all-zero struct a failed sample used to be.
//
// Kept out of cpu.go on purpose: parsefloat_governance_test.go keys its
// exemptions by cpu.go line number.
func (s *cpuSample) UnmarshalJSON(b []byte) error {
	type plain cpuSample
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		return err
	}
	if _, explicit := keys["ok"]; !explicit {
		p.OK = p.UsagePct != 0 || p.StealPct != 0 || p.IowaitPct != 0 ||
			p.CtxSwitchRate != 0 || p.RunQueue != 0 || p.ProcsBlocked != 0
	}
	*s = cpuSample(p)
	return nil
}
