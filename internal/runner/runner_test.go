package runner

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

type mockCollector struct {
	name    string
	delay   time.Duration
	result  interface{}
	err     error
	timeout time.Duration
}

func (m *mockCollector) Name() string           { return m.name }
func (m *mockCollector) Timeout() time.Duration { return m.timeout }
func (m *mockCollector) Collect(ctx context.Context) (interface{}, error) {
	select {
	case <-time.After(m.delay):
		return m.result, m.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func collectAll(ch <-chan Result) []Result {
	var results []Result
	for r := range ch {
		results = append(results, r)
	}
	return results
}

func TestRunAll_AllComplete(t *testing.T) {
	delays := []time.Duration{10, 50, 100, 200, 500}
	collectors := make([]Collector, len(delays))
	for i, d := range delays {
		collectors[i] = &mockCollector{
			name:    d.String(),
			delay:   d * time.Millisecond,
			result:  d,
			timeout: 2 * time.Second,
		}
	}

	ctx := context.Background()
	start := time.Now()
	ch := RunAll(ctx, collectors)

	var results []Result
	var timestamps []time.Duration
	for r := range ch {
		results = append(results, r)
		timestamps = append(timestamps, time.Since(start))
	}

	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}

	// Fastest result should arrive well before the slowest
	minTS := timestamps[0]
	maxTS := timestamps[0]
	for _, ts := range timestamps {
		if ts < minTS {
			minTS = ts
		}
		if ts > maxTS {
			maxTS = ts
		}
	}
	if maxTS-minTS < 200*time.Millisecond {
		t.Errorf("results arrived too close together (%v gap); streaming not working", maxTS-minTS)
	}
}

func TestRunAll_CollectorError(t *testing.T) {
	sentinel := errors.New("collector failed")
	collectors := []Collector{
		&mockCollector{name: "good", delay: 10 * time.Millisecond, result: "data", timeout: time.Second},
		&mockCollector{name: "bad", delay: 20 * time.Millisecond, err: sentinel, timeout: time.Second},
		&mockCollector{name: "good2", delay: 30 * time.Millisecond, result: "data2", timeout: time.Second},
	}

	results := collectAll(RunAll(context.Background(), collectors))
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	var errResult *Result
	for i := range results {
		if results[i].Name == "bad" {
			errResult = &results[i]
		}
	}
	if errResult == nil {
		t.Fatal("missing result for bad collector")
	}
	if !errors.Is(errResult.Err, sentinel) {
		t.Errorf("expected sentinel error, got %v", errResult.Err)
	}

	// Other collectors still complete without error
	for _, r := range results {
		if r.Name != "bad" && r.Err != nil {
			t.Errorf("collector %q unexpected error: %v", r.Name, r.Err)
		}
	}
}

func TestRunAll_ContextCancellation(t *testing.T) {
	collectors := []Collector{
		&mockCollector{name: "fast", delay: 20 * time.Millisecond, result: "x", timeout: time.Second},
		&mockCollector{name: "slow", delay: 2 * time.Second, result: "y", timeout: 5 * time.Second},
		&mockCollector{name: "slow2", delay: 2 * time.Second, result: "z", timeout: 5 * time.Second},
	}

	goroutinesBefore := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	ch := RunAll(ctx, collectors)

	// Cancel after the fast collector likely completes
	time.AfterFunc(50*time.Millisecond, cancel)

	// Drain channel — must close eventually
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("channel did not close after context cancellation")
	}

	// Give goroutines a moment to exit
	time.Sleep(20 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()

	// Allow a small delta for test framework goroutines
	if goroutinesAfter > goroutinesBefore+3 {
		t.Errorf("possible goroutine leak: before=%d after=%d", goroutinesBefore, goroutinesAfter)
	}
}

func TestRunAll_Timeout(t *testing.T) {
	collectors := []Collector{
		&mockCollector{
			name:    "sleepy",
			delay:   200 * time.Millisecond,
			result:  "never",
			timeout: 50 * time.Millisecond,
		},
	}

	start := time.Now()
	results := collectAll(RunAll(context.Background(), collectors))
	elapsed := time.Since(start)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !errors.Is(results[0].Err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded, got %v", results[0].Err)
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("result arrived too late (%v); timeout not firing", elapsed)
	}
}
