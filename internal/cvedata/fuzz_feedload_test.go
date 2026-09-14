package cvedata

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// Fuzzes the compressed-feed load path — LoadKEV / LoadSnapshot — which ingest
// a CISA KEV catalog or a pre-converted CVE snapshot that dsd downloaded (or an
// operator dropped in a standard path). The gzip->JSON decode is bounded by
// boundDecompressed (512MiB) against a decompression bomb; the OVAL *parser* is
// already fuzzed (FuzzParseUbuntuOVAL) but this gz->JSON feed-load path was not.
// Property: never panics, on arbitrary bytes, across BOTH the plain-.json and
// gzipped-.json.gz branches. A parse error is the correct, safe outcome.

func gzFeed(tb testing.TB, data []byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

func writeFeed(tb testing.TB, name string, data []byte) string {
	tb.Helper()
	p := filepath.Join(tb.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		tb.Fatalf("write feed: %v", err)
	}
	return p
}

func FuzzLoadKEV(f *testing.F) {
	f.Add([]byte(`{"catalogVersion":"2024.01.01","dateReleased":"2024-01-01","vulnerabilities":[{"cveID":"CVE-2024-0001","vendorProject":"v","product":"p","vulnerabilityName":"n","dateAdded":"2024-01-01","dueDate":"2024-02-01","knownRansomwareCampaignUse":"Unknown"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"vulnerabilities":null}`))
	f.Add([]byte(`{"vulnerabilities":[{"cveID":""}]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadKEV(writeFeed(t, "kev.json", data))               // plain JSON path
		_, _ = LoadKEV(writeFeed(t, "kev.json.gz", gzFeed(t, data))) // gzip + bound + JSON
	})
}

func FuzzLoadSnapshot(f *testing.F) {
	f.Add([]byte(`{"_generated":"2024-01-01T00:00:00Z","_source":"test","cves":{"CVE-2024-0001":{"summary":"s","severity":"high","affected":{"ubuntu":[{"name":"pkg","fixed_in":"1.0"}]}}}}`))
	f.Add([]byte(`{"cves":{}}`))
	f.Add([]byte(`{"cves":null}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadSnapshot(writeFeed(t, "snap.json", data))
		_, _ = LoadSnapshot(writeFeed(t, "snap.json.gz", gzFeed(t, data)))
	})
}
