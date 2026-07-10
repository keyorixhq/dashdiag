//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestRancherDeployReady(t *testing.T) {
	// `kubectl get deploy rancher -n cattle-system --no-headers` READY column = "0/1".
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{Stdout: []byte("rancher   0/1     1            0           2m")}
	}}
	defer SetSource(SetSource(fake))
	ready, desired := rancherDeployReady(context.Background(), "kubectl", "rancher", "cattle-system")
	if ready != 0 || desired != 1 {
		t.Fatalf("got %d/%d, want 0/1", ready, desired)
	}
}

// TestRancherDeployReadyTooFewFields guards the `len(fields) < 2` branch: a
// stdout with only one field (e.g. just the deployment name, a malformed or
// truncated --no-headers line) must return 0/0, not panic on an out-of-range
// index.
func TestRancherDeployReadyTooFewFields(t *testing.T) {
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{Stdout: []byte("rancher")}
	}}
	defer SetSource(SetSource(fake))
	if r, d := rancherDeployReady(context.Background(), "kubectl", "rancher", "cattle-system"); r != 0 || d != 0 {
		t.Fatalf("too-few-fields output must be 0/0, got %d/%d", r, d)
	}
}

// TestRancherDeployReadyNoSlashInReadyColumn guards the `len(rd) != 2`
// branch: a READY column with no "/" separator (garbled kubectl output) must
// return 0/0 rather than index into a 1-element split.
func TestRancherDeployReadyNoSlashInReadyColumn(t *testing.T) {
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{Stdout: []byte("rancher   garbled     1            0           2m")}
	}}
	defer SetSource(SetSource(fake))
	if r, d := rancherDeployReady(context.Background(), "kubectl", "rancher", "cattle-system"); r != 0 || d != 0 {
		t.Fatalf("a READY column with no '/' must be 0/0, got %d/%d", r, d)
	}
}

func TestRancherDeployReadyAbsent(t *testing.T) {
	// An absent deployment (kubectl NotFound, non-zero exit) must read 0/0 — not a
	// panic and not a phantom replica that would false-WARN.
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{Stderr: []byte("Error from server (NotFound)"), ExitCode: 1}
	}}
	defer SetSource(SetSource(fake))
	if r, d := rancherDeployReady(context.Background(), "kubectl", "rancher-webhook", "cattle-system"); r != 0 || d != 0 {
		t.Fatalf("absent deploy must be 0/0, got %d/%d", r, d)
	}
}
