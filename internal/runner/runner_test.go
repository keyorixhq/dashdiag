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

// blockingCollector ignores its context entirely and blocks until released —
// simulating a wedged syscall (stale NFS Statfs, hung exec) that doesn't honor
// cancellation. The runner must bound it rather than hang the whole run.
type blockingCollector struct {
	name    string
	timeout time.Duration
	release <-chan struct{}
}

func (b *blockingCollector) Name() string           { return b.name }
func (b *blockingCollector) Timeout() time.Duration { return b.timeout }
func (b *blockingCollector) Collect(ctx context.Context) (interface{}, error) {
	<-b.release // deliberately ignores ctx
	return "released", nil
}

func TestRunAll_BoundsBlockingCollector(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // unblock the parked Collect goroutine

	collectors := []Collector{
		&mockCollector{name: "good", delay: 10 * time.Millisecond, result: "ok", timeout: time.Second},
		&blockingCollector{name: "hang", timeout: 100 * time.Millisecond, release: release},
	}

	// Drain in a goroutine; the whole point is that this completes (channel
	// closes) despite a collector that never honors cancellation.
	done := make(chan map[string]Result, 1)
	go func() {
		res := map[string]Result{}
		for r := range RunAll(context.Background(), collectors) {
			res[r.Name] = r
		}
		done <- res
	}()

	select {
	case res := <-done:
		if len(res) != 2 {
			t.Fatalf("expected 2 results, got %d", len(res))
		}
		if res["good"].Err != nil || res["good"].Data != "ok" {
			t.Errorf("good collector: %+v", res["good"])
		}
		if res["hang"].Err == nil {
			t.Error("hang collector: expected a timeout error, got nil")
		}
		if res["hang"].Data != nil {
			t.Errorf("hang collector: expected nil data, got %v", res["hang"].Data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunAll did not complete within 3s — a blocking collector hung the whole run")
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
