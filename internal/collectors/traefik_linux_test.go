//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestTraefikCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewTraefikCollector()
	if c.Name() != "Traefik" {
		t.Errorf("Name() = %q, want Traefik", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestTraefikAvailable_NotReachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if TraefikAvailable() {
		t.Error("expected false when neither 8080 nor 80 is reachable")
	}
}

func TestTraefikAvailable_ReachableButBadOverview(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8080":                  {'1'},
		"http/http://127.0.0.1:8080/api/overview":  promHTTPResult(t, `not json`, 200),
		"http/https://127.0.0.1:8080/api/overview": promHTTPResult(t, `not json`, 200),
		"dial/tcp/127.0.0.1:80":                    {'0'},
	}, nil, nil)
	if TraefikAvailable() {
		t.Error("expected false when /api/overview never returns the http/{routers,...} shape")
	}
}

func TestTraefikAvailable_ZeroRoutersNotTrusted(t *testing.T) {
	// A routers total of 0 must not be treated as a confirmed identity — a
	// different service on the port that happens to return valid JSON with
	// a zero total shouldn't be mislabelled as Traefik.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8080":                  {'1'},
		"http/http://127.0.0.1:8080/api/overview":  promHTTPResult(t, `{"http":{"routers":{"total":0}}}`, 200),
		"http/https://127.0.0.1:8080/api/overview": promHTTPResult(t, `{"http":{"routers":{"total":0}}}`, 200),
		"dial/tcp/127.0.0.1:80":                    {'0'},
	}, nil, nil)
	if TraefikAvailable() {
		t.Error("expected false when routers.total is 0")
	}
}

func TestTraefikAvailable_ReachableHTTP(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8080":                 {'1'},
		"http/http://127.0.0.1:8080/api/overview": promHTTPResult(t, `{"http":{"routers":{"total":3,"errors":1,"warnings":2}}}`, 200),
	}, nil, nil)
	if !TraefikAvailable() {
		t.Error("expected true when the overview endpoint reports a non-zero routers total")
	}
}

func TestDetectTraefik_HTTPSFallbackOn80(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8080":                {'0'},
		"dial/tcp/127.0.0.1:80":                  {'1'},
		"http/http://127.0.0.1:80/api/overview":  promHTTPResult(t, ``, 500),
		"http/https://127.0.0.1:80/api/overview": promHTTPResult(t, `{"http":{"routers":{"total":1}}}`, 200),
	}, nil, nil)
	base, ov := detectTraefik(context.Background())
	if base != "https://127.0.0.1:80" {
		t.Errorf("base = %q, want https fallback on port 80", base)
	}
	if ov == nil || ov.HTTP.Routers.Total != 1 {
		t.Errorf("ov = %+v, want routers.total=1", ov)
	}
}

func TestTraefikCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewTraefikCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.TraefikInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestTraefikCollector_Collect_HappyPath(t *testing.T) {
	overview := `{"http":{"routers":{"total":5,"errors":1,"warnings":2},"services":{"errors":1},"middlewares":{"errors":0}}}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8080":                 {'1'},
		"http/http://127.0.0.1:8080/api/overview": promHTTPResult(t, overview, 200),
		"http/http://127.0.0.1:8080/api/version":  promHTTPResult(t, `{"Version":"v3.1.0"}`, 200),
	}, nil, nil)
	c := NewTraefikCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.TraefikInfo)
	if !info.Detected || !info.APIRead {
		t.Fatalf("info = %+v, want Detected=true APIRead=true", info)
	}
	if info.RoutersTotal != 5 || info.RoutersErrors != 1 || info.RoutersWarnings != 2 {
		t.Errorf("routers mismatch: %+v", info)
	}
	if info.ServicesErrors != 1 || info.MiddlewareErrors != 0 {
		t.Errorf("services/middleware mismatch: %+v", info)
	}
	if info.Version != "v3.1.0" {
		t.Errorf("Version = %q, want v3.1.0", info.Version)
	}
}

// TestTraefikCollector_Collect_VersionSanitizedAndCapped is the regression
// test for internal-collectors-33-06: Version never reaches Insight.Message
// (this collector emits no per-run message using it), so it must be both
// sanitized and length-capped at the point of assignment.
func TestTraefikCollector_Collect_VersionSanitizedAndCapped(t *testing.T) {
	esc := string(rune(27))
	overview := `{"http":{"routers":{"total":1}}}`
	longVersion := "v3.1.0" + esc + "[31m"
	for i := 0; i < 300; i++ {
		longVersion += "x"
	}
	versionBody, err := json.Marshal(struct {
		Version string `json:"Version"`
	}{Version: longVersion})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8080":                 {'1'},
		"http/http://127.0.0.1:8080/api/overview": promHTTPResult(t, overview, 200),
		"http/http://127.0.0.1:8080/api/version":  promHTTPResult(t, string(versionBody), 200),
	}, nil, nil)
	c := NewTraefikCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.TraefikInfo)
	if strings.Contains(info.Version, esc) {
		t.Errorf("Version = %q, want ESC stripped", info.Version)
	}
	if len([]rune(info.Version)) != 201 {
		t.Errorf("Version rune length = %d, want 201 (200 + ellipsis)", len([]rune(info.Version)))
	}
}

func TestTraefikCollector_Collect_VersionUnreachableStillReturnsInfo(t *testing.T) {
	overview := `{"http":{"routers":{"total":1}}}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8080":                 {'1'},
		"http/http://127.0.0.1:8080/api/overview": promHTTPResult(t, overview, 200),
		"http/http://127.0.0.1:8080/api/version":  promHTTPResult(t, ``, 500),
	}, nil, nil)
	c := NewTraefikCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.TraefikInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if info.Version != "" {
		t.Errorf("Version = %q, want empty when /api/version fails", info.Version)
	}
}
