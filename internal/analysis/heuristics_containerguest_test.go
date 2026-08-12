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

	v2 := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, CgroupV2Measured: true, MemLimitBytes: 256 << 20, CPUQuotaCores: 2}
	if hasInsightMsg(checkContainerGuest(v2), "INFO", "cgroup v1") {
		t.Errorf("cgroup v2 container must not emit any v1 note")
	}
}

// TestCheckContainerGuest_CgroupV2Unmeasured is the regression guard for
// internal-collectors-05-02: the v2 analog of TestCheckContainerGuest_CgroupV1
// above. Before the fix, CgroupV2Measured didn't exist and a v2 container with
// no readable counters silently read as "no throttling or OOM-kills" — never
// flagged unverified the way a v1 read failure already was.
func TestCheckContainerGuest_CgroupV2Unmeasured(t *testing.T) {
	base := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, MemLimitBytes: 256 << 20, CPUQuotaCores: 2}

	// Read failed (CgroupV2Measured false) → unverified INFO.
	if !hasInsightMsg(checkContainerGuest(base), "INFO", "could not be read on this cgroup v2 host") {
		t.Errorf("unmeasured v2 container must flag throttle/OOM unverified, got %+v", checkContainerGuest(base))
	}

	// Read succeeded, nothing wrong → no unverified note.
	measured := base
	measured.CgroupV2Measured = true
	if hasInsightMsg(checkContainerGuest(measured), "INFO", "cgroup v2") {
		t.Errorf("measured v2 container must NOT flag unverified, got %+v", checkContainerGuest(measured))
	}

	// Read succeeded AND throttled → real WARN still fires.
	throttled := measured
	throttled.ThrottledPct = 80
	if !hasInsightMsg(checkContainerGuest(throttled), "WARN", "throttled") {
		t.Errorf("a measured, throttled v2 container must WARN, got %+v", checkContainerGuest(throttled))
	}
}
