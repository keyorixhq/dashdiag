//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// promHTTPResult builds the JSON blob httpGetCached's Cached-key value must
// decode into: httpGetResult{Body []byte, Code int} (json.Marshal base64s Body).
func promHTTPResult(t *testing.T, body string, code int) []byte {
	t.Helper()
	v := struct {
		Body []byte `json:"body"`
		Code int    `json:"code"`
	}{Body: []byte(body), Code: code}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return data
}

func TestPrometheusCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewPrometheusCollector()
	if c.Name() != "Prometheus" {
		t.Errorf("Name() = %q, want Prometheus", c.Name())
	}
	if c.Timeout() != 6*time.Second {
		t.Errorf("Timeout() = %v, want 6s", c.Timeout())
	}
}

func TestPrometheusAvailable_NotReachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if PrometheusAvailable() {
		t.Error("expected false when 9090 is unreachable")
	}
}

func TestPrometheusAvailable_ReachableButBadBuildinfo(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9090":                             {'1'},
		"http/http://127.0.0.1:9090/api/v1/status/buildinfo":  promHTTPResult(t, `not json`, 200),
		"http/https://127.0.0.1:9090/api/v1/status/buildinfo": promHTTPResult(t, `not json`, 200),
	}, nil, nil)
	if PrometheusAvailable() {
		t.Error("expected false when the buildinfo endpoint never returns a valid success payload")
	}
}

func TestPrometheusAvailable_ReachableHTTP(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9090":                            {'1'},
		"http/http://127.0.0.1:9090/api/v1/status/buildinfo": promHTTPResult(t, `{"status":"success","data":{"version":"2.53.0"}}`, 200),
	}, nil, nil)
	if !PrometheusAvailable() {
		t.Error("expected true when the http buildinfo endpoint reports success")
	}
}

func TestDetectPrometheus_HTTPSFallback(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9090":                             {'1'},
		"http/http://127.0.0.1:9090/api/v1/status/buildinfo":  promHTTPResult(t, ``, 500),
		"http/https://127.0.0.1:9090/api/v1/status/buildinfo": promHTTPResult(t, `{"status":"success","data":{"version":"2.53.0"}}`, 200),
	}, nil, nil)
	base, version := detectPrometheus(context.Background())
	if base != "https://127.0.0.1:9090" {
		t.Errorf("base = %q, want https fallback", base)
	}
	if version != "2.53.0" {
		t.Errorf("version = %q, want 2.53.0", version)
	}
}

func TestPrometheusCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewPrometheusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PrometheusInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestPrometheusCollector_Collect_TargetsUnreachable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9090":                                {'1'},
		"http/http://127.0.0.1:9090/api/v1/status/buildinfo":     promHTTPResult(t, `{"status":"success","data":{"version":"2.53.0"}}`, 200),
		"http/http://127.0.0.1:9090/api/v1/targets?state=active": promHTTPResult(t, ``, 500),
	}, nil, nil)
	c := NewPrometheusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PrometheusInfo)
	if !info.Detected {
		t.Fatal("info.Detected = false, want true")
	}
	if info.MetricsRead {
		t.Error("MetricsRead = true, want false when targets API is unreachable")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when the targets API could not be read")
	}
}

func TestPrometheusCollector_Collect_TargetsBadJSON(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9090":                                {'1'},
		"http/http://127.0.0.1:9090/api/v1/status/buildinfo":     promHTTPResult(t, `{"status":"success","data":{"version":"2.53.0"}}`, 200),
		"http/http://127.0.0.1:9090/api/v1/targets?state=active": promHTTPResult(t, `not json`, 200),
	}, nil, nil)
	c := NewPrometheusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PrometheusInfo)
	if info.MetricsRead {
		t.Error("MetricsRead = true, want false on unparsable targets response")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when the targets response could not be parsed")
	}
}

func TestPrometheusCollector_Collect_FullHappyPath(t *testing.T) {
	targetsBody := `{"status":"success","data":{"activeTargets":[
		{"health":"up","scrapeUrl":"http://a:9100/metrics"},
		{"health":"down","scrapeUrl":"http://b:9100/metrics","lastError":"connection refused"},
		{"health":"down","scrapeUrl":"http://c:9100/metrics"}
	]}}`
	reloadBody := `{"status":"success","data":{"result":[{"value":[1720000000,"1"]}]}}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9090":                                                                {'1'},
		"http/http://127.0.0.1:9090/api/v1/status/buildinfo":                                     promHTTPResult(t, `{"status":"success","data":{"version":"2.53.0"}}`, 200),
		"http/http://127.0.0.1:9090/api/v1/targets?state=active":                                 promHTTPResult(t, targetsBody, 200),
		"http/http://127.0.0.1:9090/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, reloadBody, 200),
	}, nil, nil)

	c := NewPrometheusCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PrometheusInfo)
	if !info.Detected || info.Version != "2.53.0" {
		t.Errorf("info = %+v, want Detected=true Version=2.53.0", info)
	}
	if !info.MetricsRead {
		t.Fatal("MetricsRead = false, want true")
	}
	if info.TargetsTotal != 3 || info.TargetsDown != 2 {
		t.Errorf("TargetsTotal=%d TargetsDown=%d, want 3/2", info.TargetsTotal, info.TargetsDown)
	}
	if info.DownSample != "http://b:9100/metrics (connection refused)" {
		t.Errorf("DownSample = %q, want first down target with its lastError appended", info.DownSample)
	}
	if !info.ConfigReloadRead || !info.ConfigReloadOK {
		t.Errorf("ConfigReloadRead=%v ConfigReloadOK=%v, want true/true", info.ConfigReloadRead, info.ConfigReloadOK)
	}
}

func TestParsePromConfigReload(t *testing.T) {
	tests := []struct {
		name     string
		cached   map[string][]byte
		wantRead bool
		wantOK   bool
	}{
		{
			name: "success reload ok",
			cached: map[string][]byte{
				"http/http://x/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, `{"status":"success","data":{"result":[{"value":[1,"1"]}]}}`, 200),
			},
			wantRead: true,
			wantOK:   true,
		},
		{
			name: "success reload failed",
			cached: map[string][]byte{
				"http/http://x/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, `{"status":"success","data":{"result":[{"value":[1,"0"]}]}}`, 200),
			},
			wantRead: true,
			wantOK:   false,
		},
		{
			name: "http error",
			cached: map[string][]byte{
				"http/http://x/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, ``, 500),
			},
			wantRead: false,
		},
		{
			name:     "http not seeded at all (Cached returns error)",
			cached:   map[string][]byte{},
			wantRead: false,
		},
		{
			name: "bad status",
			cached: map[string][]byte{
				"http/http://x/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, `{"status":"error"}`, 200),
			},
			wantRead: false,
		},
		{
			name: "empty result",
			cached: map[string][]byte{
				"http/http://x/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, `{"status":"success","data":{"result":[]}}`, 200),
			},
			wantRead: false,
		},
		{
			name: "short value slice",
			cached: map[string][]byte{
				"http/http://x/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, `{"status":"success","data":{"result":[{"value":[1]}]}}`, 200),
			},
			wantRead: false,
		},
		{
			name: "non-string value[1]",
			cached: map[string][]byte{
				"http/http://x/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, `{"status":"success","data":{"result":[{"value":[1,2]}]}}`, 200),
			},
			wantRead: false,
		},
		{
			name: "bad json",
			cached: map[string][]byte{
				"http/http://x/api/v1/query?query=prometheus_config_last_reload_successful": promHTTPResult(t, `not json`, 200),
			},
			wantRead: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withCombinedFixture(t, tt.cached, nil, nil)
			info := &models.PrometheusInfo{}
			parsePromConfigReload(context.Background(), "http://x", info)
			if info.ConfigReloadRead != tt.wantRead {
				t.Errorf("ConfigReloadRead = %v, want %v", info.ConfigReloadRead, tt.wantRead)
			}
			if tt.wantRead && info.ConfigReloadOK != tt.wantOK {
				t.Errorf("ConfigReloadOK = %v, want %v", info.ConfigReloadOK, tt.wantOK)
			}
		})
	}
}
