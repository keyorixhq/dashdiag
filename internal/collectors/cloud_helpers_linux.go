//go:build linux

package collectors

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// timeSyncSearchConfigs reads standard chrony/timesyncd config files and reports
// whether any of them reference one of the given keywords (case-insensitive).
// checked is false when no config file was readable — callers never claim a
// verdict on a host whose time configuration couldn't be seen.
func timeSyncSearchConfigs(keywords []string) (checked, uses bool) {
	files := []string{
		"/etc/chrony.conf",
		"/etc/chrony/chrony.conf",
		"/etc/systemd/timesyncd.conf",
	}
	for _, pat := range []string{"/etc/chrony/conf.d/*.conf", "/etc/chrony/sources.d/*.sources"} {
		if matches, err := curSource().Glob(pat); err == nil {
			files = append(files, matches...)
		}
	}
	for _, f := range files {
		body := readFileTrimmedLocal(f)
		if body == "" {
			continue
		}
		checked = true
		low := strings.ToLower(body)
		for _, kw := range keywords {
			if strings.Contains(low, kw) {
				return true, true
			}
		}
	}
	return checked, false
}

// probeIMDSOpen checks whether an IMDS endpoint returns HTTP 200 for an
// unauthenticated GET — indicating token-less access is still accepted.
// checked is false when IMDS was unreachable.
func probeIMDSOpen(ctx context.Context, cacheKey, url string) (checked, open bool) {
	data, err := curSource().Cached(cacheKey, func() ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			return nil, e
		}
		client := &http.Client{Timeout: 2 * time.Second}
		resp, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode == http.StatusOK {
			return []byte("open"), nil
		}
		return []byte("blocked"), nil
	})
	if err != nil {
		return false, false
	}
	return true, string(data) == "open"
}
