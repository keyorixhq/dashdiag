package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckContainerGuest_CgroupV1: on cgroup v1 the throttle/OOM counters now ARE
// read (from the per-controller dirs). When the read succeeded the verdict behaves
// like v2 (no "unverified" note; real throttle still WARNs); only when the read
// FAILED is the signal flagged unverified — never a silent "no throttling" false-OK.
func TestCheckContainerGuest_CgroupV1(t *testing.T) {
	base := models.ContainerGuestInfo{InContainer: true, CgroupV2: false, MemLimitBytes: 256 << 20}

	// Read failed (CgroupV1Measured false) → unverified INFO.
	if !hasInsightMsg(checkContainerGuest(base), "INFO", "could not be read on this cgroup v1 host") {
		t.Errorf("unmeasured v1 container must flag throttle/OOM unverified, got %+v", checkContainerGuest(base))
	}

	// Read succeeded, nothing wrong → no unverified note (behaves like v2).
	measured := base
	measured.CgroupV1Measured = true
	if hasInsightMsg(checkContainerGuest(measured), "INFO", "cgroup v1") {
		t.Errorf("measured v1 container must NOT flag unverified, got %+v", checkContainerGuest(measured))
	}

	// Read succeeded AND throttled → real WARN fires (the signal is now actionable).
	throttled := measured
	throttled.ThrottledPct = 80
	if !hasInsightMsg(checkContainerGuest(throttled), "WARN", "throttled") {
		t.Errorf("a measured, throttled v1 container must WARN, got %+v", checkContainerGuest(throttled))
	}

	v2 := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, MemLimitBytes: 256 << 20, CPUQuotaCores: 2}
	if hasInsightMsg(checkContainerGuest(v2), "INFO", "cgroup v1") {
		t.Errorf("cgroup v2 container must not emit any v1 note")
	}
}
