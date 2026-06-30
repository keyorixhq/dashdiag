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
