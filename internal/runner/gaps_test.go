package runner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCol struct {
	name    string
	timeout time.Duration
	run     func(ctx context.Context) (any, error)
}

func (f fakeCol) Name() string                             { return f.name }
func (f fakeCol) Timeout() time.Duration                   { return f.timeout }
func (f fakeCol) Collect(ctx context.Context) (any, error) { return f.run(ctx) }

// A stuck collector's synthesized timeout wraps context.DeadlineExceeded, so
// callers classify it with errors.Is instead of reading the message.
func TestRunAll_TimeoutIsDeadlineExceeded(t *testing.T) {
	stuck := fakeCol{"Stuck", 20 * time.Millisecond, func(context.Context) (any, error) {
		time.Sleep(2 * time.Second)
		return nil, nil
	}}
	for r := range RunAll(context.Background(), []Collector{stuck}) {
		if !errors.Is(r.Err, context.DeadlineExceeded) {
			t.Fatalf("Err = %v, want it to wrap context.DeadlineExceeded", r.Err)
		}
	}
}

// With GapCount set (replay) each collector's Result says whether it alone hit
// a recording gap.
func TestRunAll_ReplayGapAttribution(t *testing.T) {
	var gaps atomic.Int64
	GapCount = func() int { return int(gaps.Load()) }
	defer func() { GapCount = nil }()
	clean := fakeCol{"Clean", time.Second, func(context.Context) (any, error) { return 1, nil }}
	gappy := fakeCol{"Gappy", time.Second, func(context.Context) (any, error) { gaps.Add(2); return 1, nil }}
	got := map[string]bool{}
	for r := range RunAll(context.Background(), []Collector{clean, gappy, clean}) {
		got[r.Name] = got[r.Name] || r.NotRecorded
	}
	if got["Clean"] || !got["Gappy"] {
		t.Errorf("NotRecorded = %v, want only Gappy", got)
	}
}
