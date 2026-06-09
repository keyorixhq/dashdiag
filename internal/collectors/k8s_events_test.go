package collectors

import (
	"fmt"
	"strings"
	"testing"
)

// kubectl sorts events ascending (oldest first), so with more than 10 warnings the
// MOST RECENT must be kept — keeping the oldest 10 showed stale warnings and could
// miss a recent critical one. Also, a blank/short line must not abort collection.
func TestParseK8sWarningEvents(t *testing.T) {
	var b strings.Builder
	// 12 events oldest→newest; columns: ns age type reason type/name message...
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&b, "default %dm Warning Reason%d pod/app-%d message %d\n", i, i, i, i)
	}
	out := b.String()
	// Inject a blank line and a short line that must be skipped, not abort.
	out += "\n" + "garbage\n" +
		"kube-system 1s Warning FailedCreatePodSandBox pod/flannel-x subnet.env missing\n"

	evs := parseK8sWarningEvents(out)

	if len(evs) != 10 {
		t.Fatalf("len = %d, want 10 (most recent, capped)", len(evs))
	}
	// The most recent event (the flannel one, appended last) must be present —
	// it would be dropped if we kept the oldest 10.
	last := evs[len(evs)-1]
	if !strings.Contains(last.Message, "subnet.env") {
		t.Errorf("most recent event missing; last = %+v", last)
	}
	// The two oldest (Reason0, Reason1) must have been dropped, not the recent ones.
	for _, e := range evs {
		if e.Reason == "Reason0" || e.Reason == "Reason1" {
			t.Errorf("kept an oldest event that should have been dropped: %+v", e)
		}
	}
}

// A single malformed line in the middle must not stop collection of later events.
func TestParseK8sWarningEvents_ShortLineDoesNotAbort(t *testing.T) {
	out := "default 1m Warning A pod/x msg\n" +
		"shortline\n" +
		"default 2m Warning B pod/y msg\n"
	evs := parseK8sWarningEvents(out)
	if len(evs) != 2 {
		t.Errorf("len = %d, want 2 (short line skipped, both real events kept)", len(evs))
	}
}
