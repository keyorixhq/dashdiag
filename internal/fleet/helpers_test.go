package fleet

import (
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestWithDefaults(t *testing.T) {
	d := Options{}.withDefaults()
	if d.RemoteCmd != "dsd health --json" || d.RemoteBinDir != "/tmp" {
		t.Errorf("defaults wrong: %+v", d)
	}
	if d.ConnectTimeout != 8*time.Second || d.RunTimeout != 45*time.Second || d.Concurrency != 8 {
		t.Errorf("timeout/concurrency defaults wrong: %+v", d)
	}
	// Non-default values are preserved.
	custom := Options{RemoteCmd: "x", RemoteBinDir: "/opt", ConnectTimeout: time.Second, RunTimeout: 2 * time.Second, Concurrency: 3}.withDefaults()
	if custom.RemoteCmd != "x" || custom.Concurrency != 3 || custom.ConnectTimeout != time.Second {
		t.Errorf("custom values should be preserved: %+v", custom)
	}
}

func TestSeconds(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{8 * time.Second, "8"},
		{500 * time.Millisecond, "1"}, // sub-second floors to 1
		{0, "1"},
		{90 * time.Second, "90"},
	}
	for _, tt := range tests {
		if got := seconds(tt.d); got != tt.want {
			t.Errorf("seconds(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("alpha\nbeta\ngamma"); got != "alpha" {
		t.Errorf("firstLine multi = %q", got)
	}
	if got := firstLine("single"); got != "single" {
		t.Errorf("firstLine single = %q", got)
	}
}

func TestSSHFailureReason(t *testing.T) {
	if got := sshFailureReason(nil); got != "no health output (is dsd installed on the remote?)" {
		t.Errorf("nil err message = %q", got)
	}
	// ExitError with stderr surfaces ssh's own first stderr line.
	ee := &exec.ExitError{Stderr: []byte("Permission denied (publickey).\nmore noise")}
	if got := sshFailureReason(ee); got != "Permission denied (publickey)." {
		t.Errorf("ExitError stderr = %q", got)
	}
	// Generic error falls back to its first line.
	if got := sshFailureReason(errors.New("dial tcp: connection refused\ntrace")); got != "dial tcp: connection refused" {
		t.Errorf("generic err = %q", got)
	}
}
