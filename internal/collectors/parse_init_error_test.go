package collectors

import "testing"

// TestParseInitError guards Init:Error/Init:CrashLoopBackOff detection for a
// pod's init containers — a genuinely pure function (typed structs in,
// string out, no I/O).
func TestParseInitError(t *testing.T) {
	type waitingStatus = struct {
		State struct {
			Waiting struct {
				Reason string `json:"reason"`
			} `json:"waiting"`
		} `json:"state"`
	}
	type containerRef = struct {
		Name string `json:"name"`
	}

	none := []waitingStatus{{}}
	if got := parseInitError(none, []containerRef{{Name: "init-db"}}); got != "" {
		t.Errorf("no error/crashloop reason should return empty, got %q", got)
	}

	var crashLoop waitingStatus
	crashLoop.State.Waiting.Reason = "CrashLoopBackOff"
	if got := parseInitError([]waitingStatus{crashLoop}, []containerRef{{Name: "init-db"}}); got != "init-db:CrashLoopBackOff" {
		t.Errorf("a crash-looping init container should report name:reason, got %q", got)
	}

	var errored waitingStatus
	errored.State.Waiting.Reason = "Error"
	if got := parseInitError([]waitingStatus{errored}, []containerRef{{Name: "migrate"}}); got != "migrate:Error" {
		t.Errorf("an errored init container should report name:reason, got %q", got)
	}

	// A running/pending reason (not Error/CrashLoop) must not be flagged.
	var pending waitingStatus
	pending.State.Waiting.Reason = "PodInitializing"
	if got := parseInitError([]waitingStatus{pending}, []containerRef{{Name: "init-db"}}); got != "" {
		t.Errorf("a benign waiting reason must not be flagged, got %q", got)
	}
}
