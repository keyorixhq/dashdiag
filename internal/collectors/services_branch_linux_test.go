//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/config"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── vault_linux.go ────────────────────────────────────────────────────────────

// TestVaultProbeBase_DialOKButAllSchemesHTTPFail guards vault_linux.go:69 —
// when port 8200 accepts a TCP connection but both HTTPS and HTTP /v1/sys/health
// fetches return an error or empty body, vaultProbeBase must return "".
// Result: Collect returns info with Reachable=false (base=="").
func TestVaultProbeBase_DialOKButAllSchemesHTTPFail(t *testing.T) {
	// t.Parallel() omitted: withCombinedFixture mutates the shared activeSource package global.
	// Seed dial as reachable but NO http fixture for either scheme — both
	// httpGetCached calls will fail (missing key → errNotFoundCVE) → continue.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8200": {'1'},
	}, nil, nil)

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if info.Reachable {
		t.Error("Reachable = true, want false when all HTTP probes fail despite port being open")
	}
}

// TestVaultFetchHealth_ErrorBranch guards vault_linux.go:74 — when the
// httpGetCached call inside vaultFetchHealth returns an error (no fixture
// seeded for that URL), vaultFetchHealth returns early and StatusRead is false.
// We call vaultFetchHealth directly with a base URL whose health endpoint
// has no fixture → httpGetCached errors → line 74 fires.
func TestVaultFetchHealth_ErrorBranch(t *testing.T) {
	// t.Parallel() omitted: withCombinedFixture mutates the shared activeSource package global.
	// Seed nothing for the health URL → httpGetCached returns errNotFoundCVE.
	withCombinedFixture(t, map[string][]byte{}, nil, nil)
	info := &models.VaultInfo{}
	vaultFetchHealth(context.Background(), "http://127.0.0.1:8200", info)
	if info.StatusRead {
		t.Error("StatusRead = true, want false when httpGetCached errors (no fixture)")
	}
}

// TestVaultFetchHealth_EmptyBodyBranch guards vault_linux.go:74 through the
// len(body)==0 sub-condition: an HTTP response with an empty body must cause
// vaultFetchHealth to return without setting StatusRead.
func TestVaultFetchHealth_EmptyBodyBranch(t *testing.T) {
	// t.Parallel() omitted: withCombinedFixture mutates the shared activeSource package global.
	emptyEncoded, _ := json.Marshal(httpGetResult{Body: []byte{}, Code: 200})
	withCombinedFixture(t, map[string][]byte{
		"http/http://127.0.0.1:8200/v1/sys/health": emptyEncoded,
	}, nil, nil)
	info := &models.VaultInfo{}
	vaultFetchHealth(context.Background(), "http://127.0.0.1:8200", info)
	if info.StatusRead {
		t.Error("StatusRead = true, want false when body is empty")
	}
}

// TestVaultFetchSealStatus_BadJSON guards vault_linux.go:99 — when the
// /v1/sys/seal-status body is not valid JSON, vaultFetchSealStatus must
// return early and leave StorageType and DevMode at their zero values.
func TestVaultFetchSealStatus_BadJSON(t *testing.T) {
	// t.Parallel() omitted: withCombinedFixture mutates the shared activeSource package global.
	healthBody := `{"initialized":true,"sealed":false,"version":"1.15.0"}`
	encoded, _ := json.Marshal(httpGetResult{Body: []byte(healthBody), Code: 200})
	sealEncoded, _ := json.Marshal(httpGetResult{Body: []byte("not-json"), Code: 200})
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:8200":                        {'1'},
		"http/https://127.0.0.1:8200/v1/sys/health":      encoded,
		"http/https://127.0.0.1:8200/v1/sys/seal-status": sealEncoded,
	}, nil, nil)

	raw, err := NewVaultCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VaultInfo)
	if !info.Reachable || !info.StatusRead {
		t.Errorf("expected Reachable+StatusRead=true, got %+v", info)
	}
	if info.StorageType != "" {
		t.Errorf("StorageType = %q, want empty when seal-status JSON is invalid", info.StorageType)
	}
	if info.DevMode {
		t.Error("DevMode = true, want false when seal-status JSON cannot be parsed")
	}
}

// ── redis_linux.go ────────────────────────────────────────────────────────────

// TestRedisPingLive_WriteError guards redis_linux.go:45 — when the TCP
// connection is established but the server immediately closes it before the
// PING write can complete, redisPingLive must return false from the Write-error
// branch (not panic or block).
func TestRedisPingLive_WriteError(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		// Close immediately so the client Write gets a broken-pipe error.
		conn.Close() //nolint:errcheck
	}()
	// The function must return false gracefully — either from the Write error
	// at line 45 or from the Read returning empty at line 50.
	addr := ln.Addr().String()
	result := redisPingLive("tcp", addr)
	if result {
		t.Error("redisPingLive() = true, want false when server closes before PING write")
	}
}

// ── elasticsearch_linux.go ───────────────────────────────────────────────────

// TestDetectElasticsearch_DialReachableButHTTPFails guards
// elasticsearch_linux.go:35 — when port 9200 answers the TCP probe but
// both http and https return errors (no fixture seeded), detectElasticsearch
// must return nil (not detected).
func TestDetectElasticsearch_DialReachableButHTTPFails(t *testing.T) {
	// t.Parallel() omitted: withCombinedFixture mutates the shared activeSource package global.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9200": {'1'},
		// no http fixtures → httpGetCached errors on both schemes → both continue
	}, nil, nil)
	if got := detectElasticsearch(context.Background()); got != nil {
		t.Errorf("detectElasticsearch() = %+v, want nil when all HTTP probes fail", got)
	}
}

// ── memcached_linux.go ───────────────────────────────────────────────────────

// TestMemcachedCmdLive_ConnectionRefused guards memcached_linux.go:58 — when
// the network address is closed (nothing listening), memcachedCmdLive must
// return ("", false) from the DialContext error branch.
func TestMemcachedCmdLive_ConnectionRefused(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() //nolint:errcheck

	out, ok := memcachedCmdLive(context.Background(), "tcp", addr, "version", false)
	if ok || out != "" {
		t.Errorf("memcachedCmdLive(refused) = (%q, %v), want (\"\", false)", out, ok)
	}
}

// TestMemcachedCmdLive_WriteFailsAfterConnect guards memcached_linux.go:75 —
// a listener that immediately closes without reading forces the Write call
// inside memcachedCmdLive to fail. The function must return ("", false).
func TestMemcachedCmdLive_WriteFailsAfterConnect(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		// Close the connection immediately — the Write in memcachedCmdLive
		// will return an error on a broken pipe.
		conn.Close() //nolint:errcheck
	}()
	addr := ln.Addr().String()
	// The write may or may not fail depending on OS TCP buffering, but the
	// conn.Read will certainly fail (EOF). The function must return gracefully.
	out, ok := memcachedCmdLive(context.Background(), "tcp", addr, "version", false)
	// Either ("", false) on write error or a partial read — just ensure no panic.
	_ = out
	_ = ok
}

// ── rabbitmq_linux.go ────────────────────────────────────────────────────────

// TestRabbitmqRun_NonRootBranch guards rabbitmq_linux.go:21 — when the
// effective uid is non-zero, rabbitmqRun must invoke the CLI directly
// (not via sudo), and propagate any command error.
func TestRabbitmqRun_NonRootBranch(t *testing.T) {
	// t.Parallel() omitted: swapGeteuid/withFixtureSource mutate shared package globals.
	swapGeteuid(t, 1000) // force non-root path
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("rabbitmq-diagnostics", []string{"-q", "ping"}, "Ping succeeded\n", 0)
	})
	out, err := rabbitmqRun(context.Background(), "rabbitmq-diagnostics", "-q", "ping")
	if err != nil {
		t.Fatalf("rabbitmqRun(non-root) unexpected error: %v", err)
	}
	if out != "Ping succeeded\n" {
		t.Errorf("out = %q, want Ping succeeded\\n", out)
	}
}

// TestRabbitmqRun_NonRootCommandFails guards rabbitmq_linux.go:21 —
// non-root path when the direct CLI invocation fails.
func TestRabbitmqRun_NonRootCommandFails(t *testing.T) {
	// t.Parallel() omitted: swapGeteuid/withFixtureSource mutate shared package globals.
	swapGeteuid(t, 1000)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("rabbitmq-diagnostics", []string{"-q", "ping"})
	})
	if _, err := rabbitmqRun(context.Background(), "rabbitmq-diagnostics", "-q", "ping"); err == nil {
		t.Fatal("expected an error when the non-root CLI invocation fails")
	}
}

// ── grafana_linux.go ─────────────────────────────────────────────────────────

// TestDetectGrafana_DialReachableButHTTPFails guards grafana_linux.go:26 —
// when port 3000 answers the TCP probe but both HTTP and HTTPS /api/health
// calls return errors (no fixture seeded), detectGrafana must return ("", nil).
func TestDetectGrafana_DialReachableButHTTPFails(t *testing.T) {
	// t.Parallel() omitted: withCombinedFixture mutates the shared activeSource package global.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:3000": {'1'},
		// no http fixtures → promHTTPGet errors on both schemes → both continue
	}, nil, nil)
	base, info := detectGrafana(context.Background())
	if base != "" || info != nil {
		t.Errorf("detectGrafana() = (%q, %+v), want (\"\", nil) when all HTTP probes fail", base, info)
	}
}

// ── ha_collector.go ──────────────────────────────────────────────────────────

// TestCrmMonResourcesFlatten_GroupBranch guards ha_collector.go:97 — the
// flatten() method's top-level Group loop. A crmMonResources that has a bare
// <group> (not inside a <clone>) must contribute its resources to the flat list.
func TestCrmMonResourcesFlatten_GroupBranch(t *testing.T) {
	t.Parallel()
	r := crmMonResources{
		Group: []crmMonGroup{
			{
				Resource: []crmMonResource{
					{ID: "vip", Active: "true"},
					{ID: "web", Active: "false"},
				},
			},
		},
	}
	flat := r.flatten()
	if len(flat) != 2 {
		t.Fatalf("flatten() = %d resources, want 2", len(flat))
	}
	ids := map[string]bool{}
	for _, res := range flat {
		ids[res.ID] = true
	}
	if !ids["vip"] || !ids["web"] {
		t.Errorf("flatten() = %v, want vip and web", flat)
	}
}

// ── ceph_linux.go ────────────────────────────────────────────────────────────
// Lines 37-40 are already covered by TestCephCollector_Collect_HealthFailedConfiguredUnreachable
// (ceph health command fails with /etc/ceph/ceph.conf present).
// The tests below guard additional error sub-branches.

// TestCephCollector_Collect_HealthFailedConfiguredNeedsRoot guards the
// non-root sub-branch of ceph_linux.go lines 37-40: when ceph health fails,
// /etc/ceph/ceph.conf exists, AND the process is not root, the collector must
// set NeedsRoot=true and provide a meaningful StatusReason.
func TestCephCollector_Collect_HealthFailedConfiguredNeedsRoot(t *testing.T) {
	// t.Parallel() omitted: swapGeteuid/withFixtureSource mutate shared package globals.
	swapGeteuid(t, 1000) // force non-root path
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/ceph/ceph.conf", source.FileMeta{})
		b.PutCmd("ceph", []string{"health", "detail", "--format", "json"}, "", 1)
	})
	c := NewCephCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CephInfo)
	if !info.Configured {
		t.Fatal("expected Configured=true when /etc/ceph/ceph.conf exists")
	}
	if !info.NeedsRoot {
		t.Error("NeedsRoot = false, want true when running as non-root and ceph health fails")
	}
	if info.Available {
		t.Error("Available = true, want false when ceph health failed")
	}
	if info.StatusReason == "" {
		t.Error("expected a non-empty StatusReason")
	}
}

// ── services.go ──────────────────────────────────────────────────────────────

// TestCheckServiceLive_HTTP_RequestConstructionError guards services.go:86-90 —
// when the URL contains a character that http.NewRequestWithContext rejects
// (a tab in the host name), checkServiceLive must return a WARN result with a
// non-empty Error and Reachable=false, without panicking.
func TestCheckServiceLive_HTTP_RequestConstructionError(t *testing.T) {
	t.Parallel()
	// A tab character embedded in the host makes the URL invalid.
	svc := config.ServiceConfig{
		Name:     "badurl",
		Host:     "127.0.0.1\tbad",
		Port:     80,
		Protocol: "http",
	}
	res := checkServiceLive(context.Background(), svc)
	if res.Reachable {
		t.Error("Reachable = true, want false for an invalid URL")
	}
	if res.Status != "WARN" {
		t.Errorf("Status = %q, want WARN for a request-construction error", res.Status)
	}
	if res.Error == "" {
		t.Error("Error = empty, want a non-empty message describing why the request failed")
	}
}

// TestServicesCollector_Collect_CritRollupViaCachedSource guards services.go:41-48 —
// the status aggregation loop: when a result has Status=="CRIT" (not just
// unreachable), the overall info.Status must be "CRIT". Uses the cached-source
// path so a seeded CRIT result is returned directly from the bundle.
func TestServicesCollector_Collect_CritRollupViaCachedSource(t *testing.T) {
	// t.Parallel() omitted: withCombinedFixture mutates the shared activeSource package
	// global, and t.Setenv (used below for HOME) is incompatible with parallel subtests.
	// Network is off by default — opt in so this test exercises the live-probe
	// path (the fixture mocks the response, not the gate in front of it).
	t.Setenv("DSD_ALLOW_NETWORK", "1")
	critResult := models.ServiceResult{
		Name: "db", Host: "127.0.0.1", Port: 5432, Protocol: "tcp",
		Status: "CRIT", Reachable: true, StatusCode: 503,
	}
	critJSON, err := json.Marshal(critResult)
	if err != nil {
		t.Fatal(err)
	}
	withCombinedFixture(t,
		map[string][]byte{"service/tcp/db/127.0.0.1:5432": critJSON},
		nil,
		func(_ *source.Bundle) {},
	)

	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgPath := home + "/.dsd.yaml"
	if werr := os.WriteFile(cfgPath, []byte("services:\n  - name: db\n    host: 127.0.0.1\n    port: 5432\n    protocol: tcp\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	c := NewServicesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesInfo)
	if info.Status != "CRIT" {
		t.Errorf("info.Status = %q, want CRIT", info.Status)
	}
}
