//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// esHTTPResult builds the JSON blob httpGetCached's Cached-key value must
// decode into: httpGetResult{Body []byte, Code int} (json.Marshal base64s Body).
func esHTTPResult(t *testing.T, body string, code int) []byte {
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

func TestElasticsearchCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewElasticsearchCollector()
	if c.Name() != "Elasticsearch" {
		t.Errorf("Name() = %q, want Elasticsearch", c.Name())
	}
	if c.Timeout() != 6*time.Second {
		t.Errorf("Timeout() = %v, want 6s", c.Timeout())
	}
}

func TestDetectElasticsearch_PortUnreachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if got := detectElasticsearch(context.Background()); got != nil {
		t.Errorf("detectElasticsearch() = %+v, want nil", got)
	}
	if ElasticsearchAvailable() {
		t.Error("ElasticsearchAvailable() = true, want false")
	}
}

func TestDetectElasticsearch_HTTPSuccess(t *testing.T) {
	body := `{"cluster_name":"escluster","tagline":"You Know, for Search","version":{"number":"8.13.0","distribution":""}}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":     {'1'},
		"http/http://127.0.0.1:9200/": esHTTPResult(t, body, 200),
	}, nil, nil)
	info := detectElasticsearch(context.Background())
	if info == nil {
		t.Fatal("detectElasticsearch() = nil, want a result")
	}
	if !info.Detected || info.BaseURL != "http://127.0.0.1:9200" {
		t.Errorf("info = %+v, want Detected=true BaseURL=http://127.0.0.1:9200", info)
	}
	if info.ClusterName != "escluster" || info.Version != "8.13.0" {
		t.Errorf("info = %+v, want ClusterName=escluster Version=8.13.0", info)
	}
	if info.Distribution != "elasticsearch" {
		t.Errorf("Distribution = %q, want elasticsearch (empty defaults)", info.Distribution)
	}
}

func TestDetectElasticsearch_HTTPFailsHTTPSSucceeds(t *testing.T) {
	body := `{"cluster_name":"escluster","tagline":"You Know, for Search","version":{"number":"8.13.0","distribution":"opensearch"}}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":      {'1'},
		"http/http://127.0.0.1:9200/":  esHTTPResult(t, ``, 500),
		"http/https://127.0.0.1:9200/": esHTTPResult(t, body, 200),
	}, nil, nil)
	info := detectElasticsearch(context.Background())
	if info == nil {
		t.Fatal("detectElasticsearch() = nil, want a result via https fallback")
	}
	if info.BaseURL != "https://127.0.0.1:9200" {
		t.Errorf("BaseURL = %q, want https fallback", info.BaseURL)
	}
	if info.Distribution != "opensearch" {
		t.Errorf("Distribution = %q, want opensearch", info.Distribution)
	}
}

func TestDetectElasticsearch_401SecurityEnabled(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":     {'1'},
		"http/http://127.0.0.1:9200/": esHTTPResult(t, ``, 401),
	}, nil, nil)
	info := detectElasticsearch(context.Background())
	if info == nil {
		t.Fatal("detectElasticsearch() = nil, want a result on 401")
	}
	if !info.Detected || info.BaseURL != "http://127.0.0.1:9200" {
		t.Errorf("info = %+v, want Detected=true BaseURL set", info)
	}
	if info.ClusterName != "" || info.Version != "" {
		t.Errorf("info = %+v, want no cluster identity on 401", info)
	}
}

func TestDetectElasticsearch_NonAuthErrorFallsThroughThenNil(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":      {'1'},
		"http/http://127.0.0.1:9200/":  esHTTPResult(t, `not json`, 500),
		"http/https://127.0.0.1:9200/": esHTTPResult(t, `not json`, 500),
	}, nil, nil)
	if got := detectElasticsearch(context.Background()); got != nil {
		t.Errorf("detectElasticsearch() = %+v, want nil when both schemes error", got)
	}
}

func TestDetectElasticsearch_BodyNotRecognized(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":      {'1'},
		"http/http://127.0.0.1:9200/":  esHTTPResult(t, `{"tagline":"hello"}`, 200),
		"http/https://127.0.0.1:9200/": esHTTPResult(t, `{"tagline":"hello"}`, 200),
	}, nil, nil)
	if got := detectElasticsearch(context.Background()); got != nil {
		t.Errorf("detectElasticsearch() = %+v, want nil (no cluster_name, no Search in tagline)", got)
	}
}

func TestElasticsearchCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewElasticsearchCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ElasticsearchInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestElasticsearchCollector_Collect_FullHappyPath(t *testing.T) {
	rootBody := `{"cluster_name":"escluster","tagline":"You Know, for Search","version":{"number":"8.13.0"}}`
	healthBody := `{"cluster_name":"","status":"yellow","number_of_nodes":1,"unassigned_shards":2,"active_shards_percent_as_number":80.5}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":                    {'1'},
		"http/http://127.0.0.1:9200/":                esHTTPResult(t, rootBody, 200),
		"http/http://127.0.0.1:9200/_cluster/health": esHTTPResult(t, healthBody, 200),
	}, nil, nil)

	c := NewElasticsearchCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ElasticsearchInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if !info.HealthRead {
		t.Fatal("HealthRead = false, want true")
	}
	if info.Status != "yellow" || info.Nodes != 1 || info.UnassignedShards != 2 || info.ActiveShardsPct != 80.5 {
		t.Errorf("info = %+v, want Status=yellow Nodes=1 UnassignedShards=2 ActiveShardsPct=80.5", info)
	}
	// Health response's cluster_name is empty -- the detect step's ClusterName must be preserved.
	if info.ClusterName != "escluster" {
		t.Errorf("ClusterName = %q, want escluster (preserved from detect)", info.ClusterName)
	}
}

// TestElasticsearchCollector_Collect_ClusterNameFromHealthWhenDetectEmpty
// guards the info.ClusterName=="" branch: when detectElasticsearch
// couldn't establish a cluster identity (401, security enabled — root probe
// returns no body identity) but the health endpoint call itself succeeds and
// carries a cluster_name, Collect must populate ClusterName from the health
// response rather than leaving it empty.
func TestElasticsearchCollector_Collect_ClusterNameFromHealthWhenDetectEmpty(t *testing.T) {
	healthBody := `{"cluster_name":"secured-cluster","status":"green","number_of_nodes":3}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":                    {'1'},
		"http/http://127.0.0.1:9200/":                esHTTPResult(t, ``, 401),
		"http/http://127.0.0.1:9200/_cluster/health": esHTTPResult(t, healthBody, 200),
	}, nil, nil)

	c := NewElasticsearchCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ElasticsearchInfo)
	if info.ClusterName != "secured-cluster" {
		t.Errorf("ClusterName = %q, want secured-cluster (populated from health response)", info.ClusterName)
	}
}

func TestElasticsearchCollector_Collect_HealthEndpointErrors(t *testing.T) {
	rootBody := `{"cluster_name":"escluster","tagline":"You Know, for Search","version":{"number":"8.13.0"}}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":                    {'1'},
		"http/http://127.0.0.1:9200/":                esHTTPResult(t, rootBody, 200),
		"http/http://127.0.0.1:9200/_cluster/health": esHTTPResult(t, ``, 500),
	}, nil, nil)

	c := NewElasticsearchCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ElasticsearchInfo)
	if info.HealthRead {
		t.Error("HealthRead = true, want false")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when cluster health is unavailable")
	}
}

func TestElasticsearchCollector_Collect_HealthResponseUnparseable(t *testing.T) {
	rootBody := `{"cluster_name":"escluster","tagline":"You Know, for Search","version":{"number":"8.13.0"}}`
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":                    {'1'},
		"http/http://127.0.0.1:9200/":                esHTTPResult(t, rootBody, 200),
		"http/http://127.0.0.1:9200/_cluster/health": esHTTPResult(t, `not json`, 200),
	}, nil, nil)

	c := NewElasticsearchCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ElasticsearchInfo)
	if info.HealthRead {
		t.Error("HealthRead = true, want false")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when the health response can't be parsed")
	}
}

// TestElasticsearchCollector_Collect_DistinctStatusReasons is a regression
// guard: the HTTP-error branch and the parse-failure branch must produce
// DIFFERENT StatusReason strings so a caller can distinguish "couldn't reach"
// from "reached but got garbage".
func TestElasticsearchCollector_Collect_DistinctStatusReasons(t *testing.T) {
	rootBody := `{"cluster_name":"escluster","tagline":"You Know, for Search","version":{"number":"8.13.0"}}`

	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":                    {'1'},
		"http/http://127.0.0.1:9200/":                esHTTPResult(t, rootBody, 200),
		"http/http://127.0.0.1:9200/_cluster/health": esHTTPResult(t, ``, 500),
	}, nil, nil)
	c := NewElasticsearchCollector()
	raw1, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	reason1 := raw1.(*models.ElasticsearchInfo).StatusReason

	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200":                    {'1'},
		"http/http://127.0.0.1:9200/":                esHTTPResult(t, rootBody, 200),
		"http/http://127.0.0.1:9200/_cluster/health": esHTTPResult(t, `not json`, 200),
	}, nil, nil)
	raw2, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	reason2 := raw2.(*models.ElasticsearchInfo).StatusReason

	if reason1 == "" || reason2 == "" {
		t.Fatalf("both reasons must be set, got %q and %q", reason1, reason2)
	}
	if reason1 == reason2 {
		t.Errorf("expected distinct StatusReason strings, both were %q", reason1)
	}
}
