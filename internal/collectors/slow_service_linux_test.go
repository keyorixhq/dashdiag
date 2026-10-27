//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// DD-COLLECTOR-GAPS-1 Medium #9: a service that accepts connections but is too
// overloaded to finish its handshake must read as "present, probe timed out",
// never as "not installed".

func seedListener(port, proc, pid string) func(b *source.Bundle) {
	return func(b *source.Bundle) {
		b.PutCmd("ss", []string{"-tlnp"},
			"LISTEN 0 128 127.0.0.1:"+port+" 0.0.0.0:* users:((\""+proc+"\",pid="+pid+",fd=8))\n", 0)
		b.PutFile("/proc/"+pid+"/cmdline", []byte("/usr/bin/"+proc+"\x00"))
	}
}

func TestGrafanaCollector_PortOpenButHealthSilentIsPresentNotAbsent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"dial/tcp/127.0.0.1:3000": {'1'}}, nil, seedListener("3000", "grafana", "77"))
	raw, err := NewGrafanaCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.GrafanaInfo)
	if !info.Detected || info.HealthRead || info.StatusReason == "" {
		t.Fatalf("info = %+v, want Detected, HealthRead=false with a reason", info)
	}
	if !GrafanaAvailable() {
		t.Error("GrafanaAvailable() = false: the collector would never be registered")
	}
}

func TestGrafanaCollector_PortOpenButNotGrafanaStaysAbsent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"dial/tcp/127.0.0.1:3000": {'1'}}, nil, seedListener("3000", "someapp", "78"))
	raw, _ := NewGrafanaCollector().Collect(context.Background())
	if raw.(*models.GrafanaInfo).Detected {
		t.Fatal("a non-grafana listener on :3000 was reported as Grafana")
	}
}

func TestMemcachedCollector_PortOpenButNoVersionIsPresentNotAbsent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:11211":              {'1'},
		"memcached/tcp/127.0.0.1:11211/version": []byte(`{"out":"","ok":false}`),
		"memcached/tcp/[::1]:11211/version":     []byte(`{"out":"","ok":false}`),
	}, nil, seedListener("11211", "memcached", "88"))
	raw, err := NewMemcachedCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.MemcachedInfo)
	if !info.Detected || info.MetricsRead || info.StatusReason == "" {
		t.Fatalf("info = %+v, want Detected, MetricsRead=false with a reason", info)
	}
}

func TestMemcachedCollector_PortClosedStaysAbsent(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	raw, _ := NewMemcachedCollector().Collect(context.Background())
	if raw.(*models.MemcachedInfo).Detected {
		t.Fatal("memcached reported with nothing listening")
	}
}
