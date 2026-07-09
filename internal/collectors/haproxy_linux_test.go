//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestHAProxyCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewHAProxyCollector()
	if c.Name() != "HAProxy" {
		t.Errorf("Name() = %q, want HAProxy", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestHAProxyAvailable(t *testing.T) {
	t.Run("running", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"200"})
			b.PutDir("/proc/200", []string{"comm"})
			b.PutFile("/proc/200/comm", []byte("haproxy\n"))
		})
		if !HAProxyAvailable() {
			t.Error("HAProxyAvailable() = false, want true")
		}
	})

	t.Run("not running", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"200"})
			b.PutDir("/proc/200", []string{"comm"})
			b.PutFile("/proc/200/comm", []byte("nginx\n"))
		})
		if HAProxyAvailable() {
			t.Error("HAProxyAvailable() = true, want false")
		}
	})
}

// TestHAProxyCollector_Collect_NotDetected guards the gate-off path: no
// haproxy process running must return Detected=false without probing version
// or config.
func TestHAProxyCollector_Collect_NotDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{"1"})
		b.PutDir("/proc/1", []string{"comm"})
		b.PutFile("/proc/1/comm", []byte("systemd\n"))
	})
	c := NewHAProxyCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAProxyInfo)
	if info.Detected {
		t.Errorf("expected Detected=false when haproxy isn't running, got %+v", info)
	}
}

// TestHAProxyCollector_Collect_HappyPath exercises the full detected path:
// haproxy running, version parsed, config test valid.
func TestHAProxyCollector_Collect_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{"300"})
		b.PutDir("/proc/300", []string{"comm"})
		b.PutFile("/proc/300/comm", []byte("haproxy\n"))
		b.PutCmd("haproxy", []string{"-v"}, "HAProxy version 2.8.5-1 2024/03/03\n", 0)
		b.PutCmd("haproxy", []string{"-c", "-f", "/etc/haproxy/haproxy.cfg"}, "Configuration file is valid\n", 0)
	})
	c := NewHAProxyCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAProxyInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if info.Version != "2.8.5-1" {
		t.Errorf("Version = %q, want 2.8.5-1", info.Version)
	}
	if !info.ConfigTested || !info.ConfigValid {
		t.Errorf("ConfigTested=%v ConfigValid=%v, want true/true", info.ConfigTested, info.ConfigValid)
	}
	if info.ConfigError != "" {
		t.Errorf("ConfigError = %q, want empty on a valid config", info.ConfigError)
	}
}

// TestHAProxyCollector_Collect_InvalidConfig guards the config-test-failed
// (syntax error) branch: ConfigTested stays true (the test DID run) but
// ConfigValid is false, with the first error-like line surfaced.
func TestHAProxyCollector_Collect_InvalidConfig(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{"300"})
		b.PutDir("/proc/300", []string{"comm"})
		b.PutFile("/proc/300/comm", []byte("haproxy\n"))
		b.PutCmd("haproxy", []string{"-v"}, "HAProxy version 2.8.5-1 2024/03/03\n", 0)
		b.PutCmd("haproxy", []string{"-c", "-f", "/etc/haproxy/haproxy.cfg"},
			"[ALERT] config : parsing [/etc/haproxy/haproxy.cfg:12] : unknown keyword 'bahckend'\n", 1)
	})
	c := NewHAProxyCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAProxyInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if !info.ConfigTested {
		t.Error("ConfigTested = false, want true (the command ran)")
	}
	if info.ConfigValid {
		t.Error("ConfigValid = true, want false on a syntax error")
	}
	if info.ConfigError == "" {
		t.Error("expected a non-empty ConfigError on an invalid config")
	}
}

// TestHAProxyCollector_Collect_ConfigPermissionDenied guards the "couldn't
// read the config" branch: a permission failure must NOT be reported as an
// invalid config (ran=false, not a false "invalid" verdict).
func TestHAProxyCollector_Collect_ConfigPermissionDenied(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{"300"})
		b.PutDir("/proc/300", []string{"comm"})
		b.PutFile("/proc/300/comm", []byte("haproxy\n"))
		b.PutCmd("haproxy", []string{"-v"}, "HAProxy version 2.8.5-1 2024/03/03\n", 0)
		b.PutCmd("haproxy", []string{"-c", "-f", "/etc/haproxy/haproxy.cfg"},
			"[ALERT] config : Permission denied\n", 1)
	})
	c := NewHAProxyCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HAProxyInfo)
	if info.ConfigTested {
		t.Error("ConfigTested = true, want false when the config couldn't be read (permission denied)")
	}
	if info.ConfigValid {
		t.Error("ConfigValid = true, want false on a permission-denied read")
	}
}
