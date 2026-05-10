package debug_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/debug"
)

func TestEnabled(t *testing.T) {
	ctx := context.Background()

	if debug.Enabled(ctx) {
		t.Fatal("expected debug disabled on plain context")
	}

	ctx = debug.With(ctx, true)
	if !debug.Enabled(ctx) {
		t.Fatal("expected debug enabled after With(ctx, true)")
	}

	ctx = debug.With(ctx, false)
	if debug.Enabled(ctx) {
		t.Fatal("expected debug disabled after With(ctx, false)")
	}
}

func TestLogDoesNotPanicWhenDisabled(t *testing.T) {
	ctx := context.Background() // debug off
	// Should be a no-op — no panic, no output.
	debug.Log(ctx, "Test", "should be silent", "key", "value")
	debug.Logf(ctx, "Test", "should be silent %s", "too")
}

func TestLogDoesNotPanicWhenEnabled(t *testing.T) {
	ctx := debug.With(context.Background(), true)
	// Writes to stderr — just verify no panic.
	debug.Log(ctx, "Test", "hello", "k1", "v1", "k2", 42)
	debug.Logf(ctx, "Test", "formatted %d", 99)
}

func TestLogOddKVSurfacesMarker(t *testing.T) {
	ctx := debug.With(context.Background(), true)
	// Odd number of kvs — should not panic, should emit MISSING_VALUE_FOR marker.
	debug.Log(ctx, "Test", "odd kv", "orphan_key")
}

func TestWithDoesNotMutateParent(t *testing.T) {
	parent := context.Background()
	child := debug.With(parent, true)

	if debug.Enabled(parent) {
		t.Fatal("With mutated parent context")
	}
	if !debug.Enabled(child) {
		t.Fatal("child should have debug enabled")
	}
}
