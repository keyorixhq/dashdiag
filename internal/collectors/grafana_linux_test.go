//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestGrafanaCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewGrafanaCollector()
	if c.Name() != "Grafana" {
		t.Errorf("Name() = %q, want Grafana", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestGrafanaAvailable_NotReachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if GrafanaAvailable() {
		t.Error("expected false when 3000 is unreachable")
	}
}

func TestGrafanaAvailable_ReachableButEmptyBody(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:3000":                {'1'},
		"http/http://127.0.0.1:3000/api/health":  promHTTPResult(t, `{}`, 200),
		"http/https://127.0.0.1:3000/api/health": promHTTPResult(t, `{}`, 200),
	}, nil, nil)
	if GrafanaAvailable() {
		t.Error("expected false when neither database nor version fields are present")
	}
}

func TestGrafanaAvailable_ReachableHTTP(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:3000":               {'1'},
		"http/http://127.0.0.1:3000/api/health": promHTTPResult(t, `{"database":"ok","version":"11.1.0","commit":"abc123"}`, 200),
	}, nil, nil)
	if !GrafanaAvailable() {
		t.Error("expected true when /api/health returns the Grafana shape")
	}
}

// TestGrafanaAvailable_DatabaseDownStillParsed guards the doc-comment
// contract: /api/health can return 503 when the database is down, but the
// body is still parsed regardless of status code (unlike other detectors
// that require 200).
func TestGrafanaAvailable_DatabaseDownStillParsed(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:3000":               {'1'},
		"http/http://127.0.0.1:3000/api/health": promHTTPResult(t, `{"database":"failing","version":"11.1.0"}`, 503),
	}, nil, nil)
	if !GrafanaAvailable() {
		t.Error("expected true even with a 503 status, as long as the body parses")
	}
}

func TestDetectGrafana_HTTPSFallback(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:3000":                {'1'},
		"http/http://127.0.0.1:3000/api/health":  promHTTPResult(t, `not json`, 200),
		"http/https://127.0.0.1:3000/api/health": promHTTPResult(t, `{"database":"ok","version":"11.1.0"}`, 200),
	}, nil, nil)
	base, info := detectGrafana(context.Background())
	if base != "https://127.0.0.1:3000" {
		t.Errorf("base = %q, want https fallback", base)
	}
	if info == nil || info.Version != "11.1.0" {
		t.Errorf("info = %+v, want Version=11.1.0", info)
	}
}

func TestGrafanaCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewGrafanaCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.GrafanaInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestGrafanaCollector_Collect_HappyPath(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:3000":               {'1'},
		"http/http://127.0.0.1:3000/api/health": promHTTPResult(t, `{"database":"ok","version":"11.1.0","commit":"abc123"}`, 200),
	}, nil, nil)
	c := NewGrafanaCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.GrafanaInfo)
	if !info.Detected || !info.HealthRead {
		t.Fatalf("info = %+v, want Detected=true HealthRead=true", info)
	}
	if !info.DatabaseOK || info.DatabaseStatus != "ok" || info.Version != "11.1.0" {
		t.Errorf("info mismatch: %+v", info)
	}
}

func TestGrafanaCollector_Collect_DatabaseNotOK(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:3000":               {'1'},
		"http/http://127.0.0.1:3000/api/health": promHTTPResult(t, `{"database":"failing","version":"11.1.0"}`, 503),
	}, nil, nil)
	c := NewGrafanaCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.GrafanaInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if info.DatabaseOK {
		t.Error("DatabaseOK = true, want false when database status is not \"ok\"")
	}
}
