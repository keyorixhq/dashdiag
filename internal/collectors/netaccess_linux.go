//go:build linux

package collectors

// netaccess_linux.go — Linux-only service-probe helpers routed through the active
// source. Service collectors gate on a reachability check (dialReachable, in the
// cross-platform netaccess.go) and then read the service over HTTP; that HTTP read
// is a live op that bypasses the file/command wrappers, so these helpers record it
// on capture and serve it on replay.

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

// dialReachable reports whether addr accepts a connection (the common gate),
// routed through the source cache. See dialOutcome.
func dialReachable(network, addr string, timeout time.Duration) bool {
	return dialOutcome(network, addr, timeout) == dialOK
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
