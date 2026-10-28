package source

import (
	"errors"
	"testing"
)

// A Replay counts reads the bundle never recorded, except a best-effort size probe.
func TestReplayGapCounting(t *testing.T) {
	rp := NewReplay(&Bundle{})
	if _, err := rp.ReadFile("/sys/x"); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("ReadFile err = %v, want ErrNotRecorded", err)
	}
	if rp.Gaps() != 1 {
		t.Fatalf("Gaps = %d after one unrecorded read, want 1", rp.Gaps())
	}
	if _, err := StatProbe(rp, "/sys/x"); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("StatProbe err = %v, want ErrNotRecorded", err)
	}
	if rp.Gaps() != 1 {
		t.Errorf("a size probe must not count as a gap, Gaps = %d", rp.Gaps())
	}
	if _, err := rp.Stat("/sys/x"); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("Stat err = %v", err)
	}
	if rp.Gaps() != 2 {
		t.Errorf("a real Stat miss is a gap (an existence gate reads it as present), Gaps = %d", rp.Gaps())
	}
}
