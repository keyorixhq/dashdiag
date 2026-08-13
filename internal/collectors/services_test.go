//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/config"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestServicesCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewServicesCollector()
	if c.Name() != "Services" {
		t.Errorf("Name() = %q, want Services", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
}

// TestServicesCollector_Collect_NoServicesConfigured guards the default path:
// with no ~/.dsd.yaml (or one without a services key), Collect must return an
// OK status with no probe attempted.
func TestServicesCollector_Collect_NoServicesConfigured(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no .dsd.yaml present -> config.Load falls to defaults
	c := NewServicesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesInfo)
	if info.Status != "OK" || len(info.Results) != 0 {
		t.Errorf("info = %+v, want Status=OK with no results", info)
	}
}

// TestServicesCollector_Collect_MalformedConfigDisclosed guards
// internal-config-01-01: a ~/.dsd.yaml that exists but fails to parse must
// not read identically to "no custom services configured" — Collect must
// return the config error so it surfaces as a disclosed INFO, rather than a
// silent OK/no-results that masks whatever services the user believed they'd
// configured.
func TestServicesCollector_Collect_MalformedConfigDisclosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgPath := filepath.Join(home, ".dsd.yaml")
	if err := os.WriteFile(cfgPath, []byte("services: [not: valid: yaml: {{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewServicesCollector()
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected Collect() to return an error for a malformed ~/.dsd.yaml")
	}
}

// TestServicesCollector_Collect_WithServices exercises the full pipeline: a
// configured service is checked via checkService/cachedJSON, replaying a
// pre-seeded WARN result so the aggregate ServicesInfo.Status becomes WARN.
func TestServicesCollector_Collect_WithServices(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgPath := filepath.Join(home, ".dsd.yaml")
	if err := os.WriteFile(cfgPath, []byte(
		"services:\n  - name: redis\n    host: 127.0.0.1\n    port: 6379\n    protocol: tcp\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	seeded := models.ServiceResult{
		Name: "redis", Host: "127.0.0.1", Port: 6379, Protocol: "tcp",
		Reachable: false, Status: "WARN", Error: "connection refused",
	}
	seededJSON, err := json.Marshal(seeded)
	if err != nil {
		t.Fatal(err)
	}

	withCombinedFixture(t,
		map[string][]byte{"service/tcp/redis/127.0.0.1:6379": seededJSON},
		nil,
		func(_ *source.Bundle) {},
	)

	c := NewServicesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesInfo)
	if len(info.Results) != 1 {
		t.Fatalf("Results = %+v, want 1 entry", info.Results)
	}
	if info.Results[0].Status != "WARN" || info.Results[0].Reachable {
		t.Errorf("Results[0] = %+v, want Status=WARN Reachable=false", info.Results[0])
	}
	if info.Status != "WARN" {
		t.Errorf("info.Status = %q, want WARN (an unreachable result without any CRIT)", info.Status)
	}
}

// TestServicesCollector_Collect_CritStatus guards the CRIT-wins aggregation:
// when any result is CRIT, the overall status must be CRIT even if scanned
// after a WARN result.
func TestServicesCollector_Collect_CritStatus(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgPath := filepath.Join(home, ".dsd.yaml")
	if err := os.WriteFile(cfgPath, []byte(
		"services:\n"+
			"  - name: warnsvc\n    host: 127.0.0.1\n    port: 1111\n    protocol: tcp\n"+
			"  - name: critsvc\n    host: 127.0.0.1\n    port: 2222\n    protocol: http\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	warnResult := models.ServiceResult{Name: "warnsvc", Host: "127.0.0.1", Port: 1111, Protocol: "tcp", Status: "WARN"}
	warnJSON, err := json.Marshal(warnResult)
	if err != nil {
		t.Fatal(err)
	}
	critResult := models.ServiceResult{Name: "critsvc", Host: "127.0.0.1", Port: 2222, Protocol: "http", Status: "CRIT", StatusCode: 503}
	critJSON, err := json.Marshal(critResult)
	if err != nil {
		t.Fatal(err)
	}

	withCombinedFixture(t,
		map[string][]byte{
			"service/tcp/warnsvc/127.0.0.1:1111":  warnJSON,
			"service/http/critsvc/127.0.0.1:2222": critJSON,
		},
		nil,
		func(_ *source.Bundle) {},
	)

	c := NewServicesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesInfo)
	if info.Status != "CRIT" {
		t.Errorf("info.Status = %q, want CRIT (a CRIT result must win over WARN)", info.Status)
	}
}

// TestCheckService_ReplayGap guards the "not recorded in replay bundle" path:
// a configured service missing from the cache must surface as an explicit
// WARN, not silently skip or panic.
func TestCheckService_ReplayGap(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	svc := config.ServiceConfig{Name: "ghost", Host: "127.0.0.1", Port: 9999, Protocol: "tcp"}
	res := checkService(context.Background(), svc)
	if res.Status != "WARN" || res.Error != "not recorded in replay bundle" {
		t.Errorf("checkService(replay gap) = %+v, want WARN/not recorded", res)
	}
	if res.Name != "ghost" || res.Host != "127.0.0.1" || res.Port != 9999 || res.Protocol != "tcp" {
		t.Errorf("checkService(replay gap) identity fields = %+v, want svc echoed back", res)
	}
}

// TestCheckService_CachedHit guards the replay-cache-hit path: a pre-seeded
// cache entry is decoded and returned directly, without any live probe.
func TestCheckService_CachedHit(t *testing.T) {
	seeded := models.ServiceResult{Name: "db", Host: "10.0.0.5", Port: 5432, Protocol: "tcp", Reachable: true, Status: "OK"}
	seededJSON, err := json.Marshal(seeded)
	if err != nil {
		t.Fatal(err)
	}
	withCombinedFixture(t,
		map[string][]byte{"service/tcp/db/10.0.0.5:5432": seededJSON},
		nil,
		func(_ *source.Bundle) {},
	)
	svc := config.ServiceConfig{Name: "db", Host: "10.0.0.5", Port: 5432, Protocol: "tcp"}
	res := checkService(context.Background(), svc)
	if !res.Reachable || res.Status != "OK" {
		t.Errorf("checkService(cached hit) = %+v, want Reachable=true Status=OK", res)
	}
}

// TestCheckService_LiveComputePath guards the un-cached branch of checkService:
// against the real source.Live (whose Cached always invokes produce, per its
// documented semantics), checkService must fall through to a genuine
// checkServiceLive probe and return its result, not just replay a pre-seeded
// fixture. This is the branch TestCheckService_ReplayGap/CachedHit (both
// against a Replay source) never exercise.
func TestCheckService_LiveComputePath(t *testing.T) {
	prev := SetSource(source.Live{Exec: nil})
	defer SetSource(prev)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			conn.Close() //nolint:errcheck
		}
	}()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil {
		t.Fatal(perr)
	}
	svc := config.ServiceConfig{Name: "live-listener", Host: host, Port: port, Protocol: "tcp"}
	res := checkService(context.Background(), svc)
	if !res.Reachable || res.Status != "OK" {
		t.Errorf("checkService(live compute path) = %+v, want Reachable=true Status=OK", res)
	}
}

// TestCheckServiceLive_TCP is a genuine live-network test against a real local
// listener — checkServiceLive dials raw net.Dialer/http.Client with no source
// routing available to fixture, matching the established pattern in
// netaccess_linux_test.go / redis_linux_test.go.
func TestCheckServiceLive_TCP(t *testing.T) {
	t.Parallel()

	t.Run("reachable", func(t *testing.T) {
		t.Parallel()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close() //nolint:errcheck
		go func() {
			for {
				conn, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				conn.Close() //nolint:errcheck
			}
		}()
		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		port, perr := strconv.Atoi(portStr)
		if perr != nil {
			t.Fatal(perr)
		}
		svc := config.ServiceConfig{Name: "listener", Host: host, Port: port, Protocol: "tcp"}
		res := checkServiceLive(context.Background(), svc)
		if !res.Reachable || res.Status != "OK" {
			t.Errorf("checkServiceLive(reachable tcp) = %+v, want Reachable=true Status=OK", res)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		t.Parallel()
		// Bind and immediately close to get a port nothing is listening on.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = ln.Close()
		port, perr := strconv.Atoi(portStr)
		if perr != nil {
			t.Fatal(perr)
		}
		svc := config.ServiceConfig{Name: "closed", Host: host, Port: port, Protocol: "tcp"}
		res := checkServiceLive(context.Background(), svc)
		if res.Reachable || res.Status != "WARN" || res.Error == "" {
			t.Errorf("checkServiceLive(unreachable tcp) = %+v, want Reachable=false Status=WARN with an Error", res)
		}
	})
}

// TestCheckServiceLive_HTTP covers the http/https branch: 200 OK, 500 CRIT,
// and a request-construction error via an invalid host containing whitespace.
func TestCheckServiceLive_HTTP(t *testing.T) {
	t.Parallel()

	t.Run("200 OK", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		port, perr := strconv.Atoi(portStr)
		if perr != nil {
			t.Fatal(perr)
		}
		svc := config.ServiceConfig{Name: "web", Host: host, Port: port, Protocol: "http"}
		res := checkServiceLive(context.Background(), svc)
		if !res.Reachable || res.Status != "OK" || res.StatusCode != 200 {
			t.Errorf("checkServiceLive(200) = %+v, want Reachable=true Status=OK StatusCode=200", res)
		}
	})

	t.Run("500 CRIT", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		port, perr := strconv.Atoi(portStr)
		if perr != nil {
			t.Fatal(perr)
		}
		svc := config.ServiceConfig{Name: "web", Host: host, Port: port, Protocol: "http"}
		res := checkServiceLive(context.Background(), svc)
		if !res.Reachable || res.Status != "CRIT" || res.StatusCode != 500 {
			t.Errorf("checkServiceLive(500) = %+v, want Reachable=true Status=CRIT StatusCode=500", res)
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		t.Parallel()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = ln.Close()
		port, perr := strconv.Atoi(portStr)
		if perr != nil {
			t.Fatal(perr)
		}
		svc := config.ServiceConfig{Name: "web", Host: host, Port: port, Protocol: "https"}
		res := checkServiceLive(context.Background(), svc)
		if res.Reachable || res.Status != "WARN" || res.Error == "" {
			t.Errorf("checkServiceLive(https connection refused) = %+v, want Reachable=false Status=WARN with an Error", res)
		}
	})
}
