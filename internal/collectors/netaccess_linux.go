//go:build linux

package collectors

// netaccess_linux.go — local-service probe helpers routed through the active
// source. Service collectors gate on a TCP/unix reachability check and then read
// the service over HTTP or a socket; both are live network ops that bypass the
// file/command wrappers, so `dsd replay` would re-probe the replaying machine.
// These helpers record the probe outcome on capture and serve it on replay.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// dialReachable reports whether addr accepts a connection, routed through the
// source cache so a "service is up" gate replays from the bundle instead of
// dialing the replaying machine. The probe never errors — unreachable is recorded
// as a "0", so replay reproduces the capture-time reachability rather than
// defaulting to a live dial. On a recording gap (older bundle) it returns false
// (don't claim a service we never observed).
func dialReachable(network, addr string, timeout time.Duration) bool {
	data, _ := activeSource.Cached("dial/"+network+"/"+addr, func() ([]byte, error) {
		conn, derr := net.DialTimeout(network, addr, timeout)
		if derr != nil {
			return []byte{'0'}, nil
		}
		_ = conn.Close()
		return []byte{'1'}, nil
	})
	return len(data) == 1 && data[0] == '1'
}

// httpGetResult is the cached form of an HTTP GET: response body + status code.
type httpGetResult struct {
	Body []byte `json:"body"`
	Code int    `json:"code"`
}

// httpGetCached performs a local HTTP GET (TLS verification skipped — local health
// probe) and routes the response through the source cache so it replays from the
// bundle instead of re-fetching live. Keyed by URL, which is unique per probe.
func httpGetCached(ctx context.Context, url string) ([]byte, int, error) {
	var r httpGetResult
	err := cachedJSON("http/"+url, func() (any, error) {
		body, code, e := httpGetLive(ctx, url)
		if e != nil {
			return nil, e
		}
		return httpGetResult{Body: body, Code: code}, nil
	}, &r)
	if err != nil {
		return nil, 0, err
	}
	return r.Body, r.Code, nil
}

func httpGetLive(ctx context.Context, url string) ([]byte, int, error) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local health probe, not a trust decision
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, nil
}
