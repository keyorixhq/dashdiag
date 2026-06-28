package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckContainerGuest_CgroupV1Unmeasured: on cgroup v1 the throttle/OOM counters
// aren't collected, so the verdict must say so rather than implying they were measured
// (the unverified-negative false-OK). On v2 no such note appears.
func TestCheckContainerGuest_CgroupV1Unmeasured(t *testing.T) {
	v1 := models.ContainerGuestInfo{
		InContainer: true, CgroupV2: false,
		MemLimitBytes: 256 << 20, // limited + non-root → no WARNs, so the summary would otherwise read green
	}
	got := checkContainerGuest(v1)
	if !hasInsightMsg(got, "INFO", "not measured on this host (cgroup v1)") {
		t.Errorf("cgroup v1 container must flag throttle/OOM as unmeasured, got %+v", got)
	}

	v2 := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, MemLimitBytes: 256 << 20, CPUQuotaCores: 2}
	if hasInsightMsg(checkContainerGuest(v2), "INFO", "cgroup v1") {
		t.Errorf("cgroup v2 container must not emit the v1-unmeasured note")
	}
}
