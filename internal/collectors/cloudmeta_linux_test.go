//go:build linux

package collectors

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// liveCachedSource mirrors source.Live's Cached semantics (always invoke
// produce) on top of a Bundle-backed Replay for everything else — needed to
// exercise imdsGet's closure body (the actual imdsGetLive call), which a plain
// Replay-backed fixture never reaches because Replay.Cached short-circuits
// without invoking produce.
type liveCachedSource struct {
	*source.Replay
}

func (liveCachedSource) Cached(_ string, produce func() ([]byte, error)) ([]byte, error) {
	return produce()
}

func withLiveCachedFixture(t *testing.T) {
	t.Helper()
	prev := SetSource(liveCachedSource{Replay: source.NewReplay(source.NewBundle())})
	t.Cleanup(func() { SetSource(prev) })
}

// ── imdsCacheKey ─────────────────────────────────────────────────────────────

func TestImdsCacheKey_NoHeaders(t *testing.T) {
	t.Parallel()
	got := imdsCacheKey("http://169.254.169.254/latest/meta-data/instance-id", nil)
	want := "imds/http://169.254.169.254/latest/meta-data/instance-id"
	if got != want {
		t.Errorf("imdsCacheKey() = %q, want %q", got, want)
	}
}

func TestImdsCacheKey_SingleHeader(t *testing.T) {
	t.Parallel()
	got := imdsCacheKey("http://169.254.169.254/latest/meta-data/instance-id",
		map[string]string{"X-aws-ec2-metadata-token": "tok"})
	want := "imds/http://169.254.169.254/latest/meta-data/instance-id#X-aws-ec2-metadata-token=tok"
	if got != want {
		t.Errorf("imdsCacheKey() = %q, want %q", got, want)
	}
}

// TestImdsCacheKey_SortedRegardlessOfMapOrder guards determinism: Go map
// iteration order is randomised, so the key must be built from a header list
// sorted by name — otherwise the same logical (url, headers) request could
// hash to a different key on different calls, defeating the cache (a miss)
// rather than just protecting it from cross-header collisions.
func TestImdsCacheKey_SortedRegardlessOfMapOrder(t *testing.T) {
	t.Parallel()
	headers := map[string]string{"Zeta": "1", "Alpha": "2", "Metadata": "true"}
	want := "imds/http://x#Alpha=2&Metadata=true&Zeta=1"
	for i := 0; i < 20; i++ { // repeat: map iteration order varies per run
		if got := imdsCacheKey("http://x", headers); got != want {
			t.Fatalf("imdsCacheKey() = %q, want %q (run %d)", got, want, i)
		}
	}
}

// TestImdsCacheKey_DifferentHeadersDoNotCollide is the regression guard for
// internal-collectors-04-02: keying imdsGet's Cached() call by URL alone meant
// two calls to the SAME URL with DIFFERENT headers (different auth
// tokens/contexts) produced the SAME key, so the second call silently got the
// first's cached response instead of its own. The header content must now be
// part of the key so differing headers for the same URL never collide.
func TestImdsCacheKey_DifferentHeadersDoNotCollide(t *testing.T) {
	t.Parallel()
	url := "http://169.254.169.254/latest/meta-data/instance-id"
	keyA := imdsCacheKey(url, map[string]string{"X-aws-ec2-metadata-token": "token-A"})
	keyB := imdsCacheKey(url, map[string]string{"X-aws-ec2-metadata-token": "token-B"})
	if keyA == keyB {
		t.Fatalf("imdsCacheKey() collided for the same URL with different header values: both = %q", keyA)
	}
}

// TestImdsCacheKey_SameURLAndHeadersMatch confirms the cache-hit path still
// works: identical (url, headers) pairs must still resolve to the identical
// key, or every legitimate cache hit becomes a miss.
func TestImdsCacheKey_SameURLAndHeadersMatch(t *testing.T) {
	t.Parallel()
	url := "http://169.254.169.254/latest/meta-data/instance-id"
	headers := map[string]string{"X-aws-ec2-metadata-token": "tok"}
	if imdsCacheKey(url, headers) != imdsCacheKey(url, headers) {
		t.Fatal("imdsCacheKey() must be deterministic for the same (url, headers) pair")
	}
}

// TestImdsGet_DifferentHeadersDoNotCollide drives imdsGet itself (not just the
// key builder) through a fake Cached source keyed by imdsCacheKey's output,
// confirming two calls to the same URL with different headers each get their
// OWN cached response rather than the first call's.
func TestImdsGet_DifferentHeadersDoNotCollide(t *testing.T) {
	url := "http://169.254.169.254/latest/meta-data/instance-id"
	withCombinedFixture(t, map[string][]byte{
		imdsCacheKey(url, map[string]string{"X-aws-ec2-metadata-token": "token-A"}): []byte("response-for-A"),
		imdsCacheKey(url, map[string]string{"X-aws-ec2-metadata-token": "token-B"}): []byte("response-for-B"),
	}, nil, nil)

	gotA, errA := imdsGet(context.Background(), url, map[string]string{"X-aws-ec2-metadata-token": "token-A"})
	if errA != nil {
		t.Fatalf("unexpected error for token-A: %v", errA)
	}
	if gotA != "response-for-A" {
		t.Errorf("imdsGet with token-A = %q, want response-for-A", gotA)
	}

	gotB, errB := imdsGet(context.Background(), url, map[string]string{"X-aws-ec2-metadata-token": "token-B"})
	if errB != nil {
		t.Fatalf("unexpected error for token-B: %v", errB)
	}
	if gotB != "response-for-B" {
		t.Errorf("imdsGet with token-B = %q, want response-for-B (must not have gotten token-A's cached response)", gotB)
	}
}

func TestParseAzureScheduledEvents(t *testing.T) {
	// A real /scheduledevents document with a pending reboot.
	const reboot = `{
		"DocumentIncarnation": 4,
		"Events": [{
			"EventId": "abc-123",
			"EventType": "Reboot",
			"ResourceType": "VirtualMachine",
			"Resources": ["myvm"],
			"EventStatus": "Scheduled",
			"NotBefore": "Mon, 23 Jun 2026 10:00:00 GMT"
		}]
	}`
	pending, details := parseAzureScheduledEvents(reboot)
	if !pending {
		t.Fatal("a scheduled Reboot must be reported as pending")
	}
	for _, want := range []string{"Reboot", "Scheduled", "Mon, 23 Jun 2026"} {
		if !strings.Contains(details, want) {
			t.Errorf("details %q missing %q", details, want)
		}
	}

	// Redeploy/Preempt/Terminate were missed by the old string match — confirm covered.
	for _, et := range []string{"Redeploy", "Preempt", "Terminate", "Freeze"} {
		body := `{"Events":[{"EventType":"` + et + `","EventStatus":"Scheduled"}]}`
		if p, d := parseAzureScheduledEvents(body); !p || !strings.Contains(d, et) {
			t.Errorf("%s event: pending=%v details=%q, want pending with type", et, p, d)
		}
	}

	// Empty event list = no pending maintenance (the normal steady state).
	if p, _ := parseAzureScheduledEvents(`{"DocumentIncarnation":1,"Events":[]}`); p {
		t.Error("empty Events list must NOT report pending")
	}

	// Garbled / empty body must never read as "event pending".
	for _, bad := range []string{"", "not json", "{}"} {
		if p, _ := parseAzureScheduledEvents(bad); p {
			t.Errorf("garbled body %q must not report pending", bad)
		}
	}
}

// TestImdsGetLive_LargeBody is a regression guard: imdsGetLive used to Read()
// into a single fixed 4096-byte buffer and return only what fit, silently
// truncating anything larger — Azure's compute/storageProfile document for a
// multi-data-disk VM routinely exceeds 4KB (each managedDisk.id is a ~200-char
// ARM resource path), truncating the JSON mid-object and making
// parseAzureStorageProfile fail closed exactly on the VMs it targets.
func TestImdsGetLive_LargeBody(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"dataDisks":[`)
	for i := range 40 {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"managedDisk":{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example-long-name/providers/Microsoft.Compute/disks/disk-`)
		sb.WriteString(strings.Repeat("x", 40))
		sb.WriteString(`"},"caching":"ReadWrite"}`)
	}
	sb.WriteString(`]}`)
	body := sb.String()
	if len(body) <= 4096 {
		t.Fatalf("test body is only %d bytes, must exceed the old 4096-byte truncation point", len(body))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := imdsGetLive(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("imdsGetLive error: %v", err)
	}
	if got != body {
		t.Errorf("response was truncated: got %d bytes, want %d", len(got), len(body))
	}
}

// TestImdsGetLive_NonOKStatus guards the fail-closed behaviour: a non-2xx
// response (404/proxy page/redirect target) must never be returned as a value
// the caller could mistake for real metadata.
func TestImdsGetLive_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got, err := imdsGetLive(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatalf("expected an error for HTTP 404, got body %q", got)
	}
	if got != "" {
		t.Errorf("got = %q, want empty on error", got)
	}
}

// TestImdsGetLive_HeadersSet confirms every supplied header reaches the
// request (the AWS/Azure/GCP/OCI token headers all route through here).
func TestImdsGetLive_HeadersSet(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Metadata-Flavor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	if _, err := imdsGetLive(context.Background(), srv.URL, map[string]string{"Metadata-Flavor": "Google"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotHeader != "Google" {
		t.Errorf("Metadata-Flavor header = %q, want Google", gotHeader)
	}
}

// TestImdsGetLive_MalformedURL guards the http.NewRequestWithContext error
// branch: a URL containing a raw control character is rejected by net/http's
// request construction before any dial is attempted — deterministic, no
// network involved.
func TestImdsGetLive_MalformedURL(t *testing.T) {
	got, err := imdsGetLive(context.Background(), "http://\x7f", nil)
	if err == nil {
		t.Fatalf("expected an error for a malformed URL, got body %q", got)
	}
	if got != "" {
		t.Errorf("got = %q, want empty on error", got)
	}
}

// TestImdsGetLive_DialFails guards the client.Do error branch: dialing a
// closed local port fails immediately with connection refused, without
// depending on any real network egress.
func TestImdsGetLive_DialFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // closed before use -> connection refused

	got, err := imdsGetLive(context.Background(), url, nil)
	if err == nil {
		t.Fatalf("expected a dial error against a closed server, got body %q", got)
	}
	if got != "" {
		t.Errorf("got = %q, want empty on error", got)
	}
}

// TestImdsGetLive_BodyReadFails guards the io.ReadAll error branch: the
// server advertises a Content-Length longer than the bytes it actually sends
// and then closes the connection, so the client's body read fails partway
// through rather than the request itself failing.
func TestImdsGetLive_BodyReadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close() // abrupt close before the promised length is sent
		}
	}))
	defer srv.Close()

	got, err := imdsGetLive(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatalf("expected a body-read error from a truncated response, got body %q", got)
	}
	if got != "" {
		t.Errorf("got = %q, want empty on error", got)
	}
}

// TestImdsGetLive_DoesNotFollowRedirect is a regression guard for
// internal-collectors-02-02: the IMDS http.Client used to follow redirects
// like any normal browser client (net/http's default is up to 10 hops). IMDS
// endpoints never legitimately redirect, so a compromised or spoofed
// responder on the link-local address could redirect the request — carrying
// the IMDSv2 session token header — to an attacker-chosen host. The fix
// (newIMDSHTTPClient) must refuse to follow the redirect: the attacker
// target must never be dialed, and the 3xx response itself must be treated
// as "not metadata" (matching the existing non-2xx fail-closed behaviour).
func TestImdsGetLive_DoesNotFollowRedirect(t *testing.T) {
	var attackerHit bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("attacker-controlled-body"))
	}))
	defer attacker.Close()

	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusFound)
	}))
	defer imds.Close()

	got, err := imdsGetLive(context.Background(), imds.URL, nil)
	if attackerHit {
		t.Fatal("imdsGetLive followed the redirect and dialed the attacker-controlled host")
	}
	if err == nil {
		t.Fatalf("expected an error for a redirect response, got body %q", got)
	}
	if got != "" {
		t.Errorf("got = %q, want empty on a refused redirect", got)
	}
}

// ── imdsGet (Cached wrapper — exercises the produce closure directly) ───────

// TestImdsGet_LiveSuccess drives imdsGet's closure (imdsGetLive call, success
// path) by installing a Cached-that-always-invokes-produce source, which a
// Replay-backed fixture never reaches (Replay.Cached short-circuits).
func TestImdsGet_LiveSuccess(t *testing.T) {
	withLiveCachedFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("i-0123456789abcdef0"))
	}))
	defer srv.Close()

	got, err := imdsGet(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "i-0123456789abcdef0" {
		t.Errorf("imdsGet() = %q, want i-0123456789abcdef0", got)
	}
}

// TestImdsGet_LiveError drives imdsGet's closure error path (a non-2xx
// response from imdsGetLive), confirming the error propagates and the value
// is empty rather than a garbage/error-page body.
func TestImdsGet_LiveError(t *testing.T) {
	withLiveCachedFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	got, err := imdsGet(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatalf("expected an error for HTTP 403, got body %q", got)
	}
	if got != "" {
		t.Errorf("got = %q, want empty on error", got)
	}
}

// ── awsIMDSToken (direct, via a fake RoundTripper) ──────────────────────────

// chunkyReadCloser simulates a response body that trickles bytes out a few
// at a time rather than handing them all back on the first Read() call — the
// io.Reader contract explicitly permits this (e.g. under chunked transfer-
// encoding), and a caller that assumes a single Read() drains the body will
// silently truncate.
type chunkyReadCloser struct {
	data      []byte
	pos       int
	chunkSize int
}

func (r *chunkyReadCloser) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := r.chunkSize
	if n > len(p) {
		n = len(p)
	}
	if remaining := len(r.data) - r.pos; n > remaining {
		n = remaining
	}
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}

func (r *chunkyReadCloser) Close() error { return nil }

// TestAwsIMDSToken_FullBodyReadAcrossMultipleReads guards Finding:
// internal-collectors-04-04. awsIMDSToken used to read the token with a
// single fixed-256-byte-buffer Read() call, discarding its error — not
// guaranteed by the io.Reader contract to drain the whole body in one call
// (e.g. under chunked transfer-encoding), so a slow/misbehaving IMDS
// responder could silently truncate the cached token. It must instead read
// the FULL body (io.ReadAll+LimitReader, matching imdsGetLive's already-
// fixed pattern), even when the underlying reader trickles bytes out a few
// at a time.
func TestAwsIMDSToken_FullBodyReadAcrossMultipleReads(t *testing.T) {
	withLiveCachedFixture(t)

	longToken := strings.Repeat("A", 300) // longer than the old 256-byte buffer
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       &chunkyReadCloser{data: []byte(longToken), chunkSize: 40},
		}, nil
	})}

	token, err := awsIMDSToken(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != longToken {
		t.Errorf("token = %d bytes (%q...), want the full %d-byte token — a short Read must not silently truncate it",
			len(token), token[:min(20, len(token))], len(longToken))
	}
}

// ── constructor / interface methods ──────────────────────────────────────────

func TestNewCloudMetaCollector_NameAndTimeout(t *testing.T) {
	c := NewCloudMetaCollector()
	if c.Name() != "CloudMeta" {
		t.Errorf("Name() = %q, want CloudMeta", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

// ── Collect (integration — provider dispatch) ────────────────────────────────

func TestCloudMetaCollector_Collect_AWS(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok"),
		"imds/http://169.254.169.254/latest/meta-data/instance-id#X-aws-ec2-metadata-token=tok":      []byte("i-0123456789abcdef0"),
		"imds/http://169.254.169.254/latest/meta-data/instance-type#X-aws-ec2-metadata-token=tok":    []byte("t3.micro"),
		"imds/http://169.254.169.254/latest/meta-data/placement/region#X-aws-ec2-metadata-token=tok": []byte("us-east-1"),
		"imds-aws-termination": []byte(`{}`),
	}, nil, nil)

	c := NewCloudMetaCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.CloudInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.CloudInfo", result)
	}
	if !info.Available || info.Provider != "aws" || info.InstanceID != "i-0123456789abcdef0" {
		t.Errorf("info = %+v, want aws provider with instance id", info)
	}
}

func TestCloudMetaCollector_Collect_NoProvider(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)

	c := NewCloudMetaCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.CloudInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.CloudInfo", result)
	}
	if info.Available || info.Provider != "" {
		t.Errorf("info = %+v, want unavailable with no provider", info)
	}
}

// TestCloudMetaCollector_Collect_Azure exercises Collect's second dispatch
// branch — AWS fails (no token), Azure succeeds.
func TestCloudMetaCollector_Collect_Azure(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/metadata/instance?api-version=2021-02-01#Metadata=true": []byte(`{"compute":{"azEnvironment":"AzurePublicCloud"}}`),
	}, nil, nil)

	c := NewCloudMetaCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.CloudInfo)
	if !info.Available || info.Provider != "azure" {
		t.Errorf("info = %+v, want azure provider", info)
	}
}

// TestCloudMetaCollector_Collect_GCP exercises Collect's third dispatch
// branch — AWS and Azure both fail, GCP succeeds.
func TestCloudMetaCollector_Collect_GCP(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/id#Metadata-Flavor=Google": []byte("1234567890"),
	}, nil, nil)

	c := NewCloudMetaCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.CloudInfo)
	if !info.Available || info.Provider != "gcp" {
		t.Errorf("info = %+v, want gcp provider", info)
	}
}

// TestCloudMetaCollector_Collect_OCI exercises Collect's fourth dispatch
// branch — AWS/Azure/GCP all fail, OCI succeeds.
func TestCloudMetaCollector_Collect_OCI(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/opc/v2/instance/#Authorization=Bearer Oracle": []byte(`{"id":"ocid1.instance.oc1..abc"}`),
	}, nil, nil)

	c := NewCloudMetaCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.CloudInfo)
	if !info.Available || info.Provider != "oci" {
		t.Errorf("info = %+v, want oci provider", info)
	}
}

// ── collectAWS ────────────────────────────────────────────────────────────────

func TestCollectAWS_Success(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok"),
		"imds/http://169.254.169.254/latest/meta-data/instance-id#X-aws-ec2-metadata-token=tok":      []byte("i-abc"),
		"imds/http://169.254.169.254/latest/meta-data/instance-type#X-aws-ec2-metadata-token=tok":    []byte("m5.large"),
		"imds/http://169.254.169.254/latest/meta-data/placement/region#X-aws-ec2-metadata-token=tok": []byte("eu-west-1"),
		"imds-aws-termination": []byte(`{}`),
	}, nil, nil)

	var info models.CloudInfo
	if !collectAWS(context.Background(), &info) {
		t.Fatal("expected collectAWS to succeed")
	}
	if info.Provider != "aws" || info.InstanceID != "i-abc" || info.InstanceType != "m5.large" || info.Region != "eu-west-1" {
		t.Errorf("info = %+v, want aws/i-abc/m5.large/eu-west-1", info)
	}
	if info.SpotTermination || info.SpotCheckFailed {
		t.Errorf("no spot notice seeded, got SpotTermination=%v SpotCheckFailed=%v", info.SpotTermination, info.SpotCheckFailed)
	}
}

func TestCollectAWS_NoToken(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	var info models.CloudInfo
	if collectAWS(context.Background(), &info) {
		t.Error("expected collectAWS to fail when the IMDS token is unavailable")
	}
}

func TestCollectAWS_TokenButNoInstanceID(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok"),
	}, nil, nil)
	var info models.CloudInfo
	if collectAWS(context.Background(), &info) {
		t.Error("expected collectAWS to fail when instance-id is unavailable")
	}
}

func TestCollectAWS_SpotTerminating(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok"),
		"imds/http://169.254.169.254/latest/meta-data/instance-id#X-aws-ec2-metadata-token=tok": []byte("i-abc"),
		"imds-aws-termination": []byte(`{"terminating":true}`),
	}, nil, nil)
	var info models.CloudInfo
	if !collectAWS(context.Background(), &info) {
		t.Fatal("expected collectAWS to succeed")
	}
	if !info.SpotTermination {
		t.Error("expected SpotTermination=true")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason explaining the spot termination")
	}
}

func TestCollectAWS_SpotCheckFailed(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok"),
		"imds/http://169.254.169.254/latest/meta-data/instance-id#X-aws-ec2-metadata-token=tok": []byte("i-abc"),
		"imds-aws-termination": []byte(`{"check_failed":true}`),
	}, nil, nil)
	var info models.CloudInfo
	if !collectAWS(context.Background(), &info) {
		t.Fatal("expected collectAWS to succeed")
	}
	if !info.SpotCheckFailed {
		t.Error("expected SpotCheckFailed=true")
	}
	if info.SpotTermination {
		t.Error("SpotTermination must not be set when the check merely failed")
	}
}

// ── awsSpotTermination (direct, via a fake RoundTripper) ─────────────────────

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAwsSpotTermination(t *testing.T) {
	tests := []struct {
		name       string
		rt         roundTripFunc
		wantTerm   bool
		wantFailed bool
	}{
		{
			name: "200 means a notice is posted",
			rt: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
			},
			wantTerm: true,
		},
		{
			name: "404 means no notice (normal case)",
			rt: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 404, Body: http.NoBody}, nil
			},
		},
		{
			name: "unexpected status could not confirm",
			rt: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 500, Body: http.NoBody}, nil
			},
			wantFailed: true,
		},
		{
			name: "request error could not confirm",
			rt: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("simulated: unreachable")
			},
			wantFailed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: tt.rt}
			got := awsSpotTermination(context.Background(), client, "tok")
			if got.Terminating != tt.wantTerm || got.CheckFailed != tt.wantFailed {
				t.Errorf("awsSpotTermination() = %+v, want Terminating=%v CheckFailed=%v", got, tt.wantTerm, tt.wantFailed)
			}
		})
	}
}

// ── collectAzure ──────────────────────────────────────────────────────────────

func TestCollectAzure_Success(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/metadata/instance?api-version=2021-02-01#Metadata=true":        []byte(`{"compute":{"azEnvironment":"AzurePublicCloud"}}`),
		"imds/http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01#Metadata=true": []byte(`{"Events":[]}`),
	}, nil, nil)
	var info models.CloudInfo
	if !collectAzure(context.Background(), &info) {
		t.Fatal("expected collectAzure to succeed")
	}
	if info.Provider != "azure" || !info.Available {
		t.Errorf("info = %+v, want azure/available", info)
	}
	if info.MaintenanceEvent {
		t.Error("no scheduled events seeded, MaintenanceEvent should be false")
	}
}

func TestCollectAzure_NotAzure(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/metadata/instance?api-version=2021-02-01#Metadata=true": []byte(`{"unrelated":"body"}`),
	}, nil, nil)
	var info models.CloudInfo
	if collectAzure(context.Background(), &info) {
		t.Error("expected collectAzure to fail when body lacks azEnvironment")
	}
}

func TestCollectAzure_NoResponse(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	var info models.CloudInfo
	if collectAzure(context.Background(), &info) {
		t.Error("expected collectAzure to fail when IMDS is unreachable")
	}
}

func TestCollectAzure_MaintenanceEvent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/metadata/instance?api-version=2021-02-01#Metadata=true":        []byte(`{"compute":{"azEnvironment":"AzurePublicCloud"}}`),
		"imds/http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01#Metadata=true": []byte(`{"Events":[{"EventType":"Reboot","EventStatus":"Scheduled"}]}`),
	}, nil, nil)
	var info models.CloudInfo
	if !collectAzure(context.Background(), &info) {
		t.Fatal("expected collectAzure to succeed")
	}
	if !info.MaintenanceEvent || !strings.Contains(info.MaintenanceDetails, "Reboot") {
		t.Errorf("info = %+v, want a pending Reboot maintenance event", info)
	}
}

// ── collectGCP ────────────────────────────────────────────────────────────────

func TestCollectGCP_Success(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/id#Metadata-Flavor=Google":           []byte("1234567890"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/machine-type#Metadata-Flavor=Google": []byte("n1-standard-1"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/zone#Metadata-Flavor=Google":         []byte("us-central1-a"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/preempted#Metadata-Flavor=Google":    []byte("FALSE"),
	}, nil, nil)
	var info models.CloudInfo
	if !collectGCP(context.Background(), &info) {
		t.Fatal("expected collectGCP to succeed")
	}
	if info.Provider != "gcp" || info.InstanceID != "1234567890" || info.InstanceType != "n1-standard-1" || info.Region != "us-central1-a" {
		t.Errorf("info = %+v, want gcp/1234567890/n1-standard-1/us-central1-a", info)
	}
	if info.SpotTermination {
		t.Error("preempted=FALSE, SpotTermination should be false")
	}
}

func TestCollectGCP_NotAvailable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	var info models.CloudInfo
	if collectGCP(context.Background(), &info) {
		t.Error("expected collectGCP to fail when IMDS is unreachable")
	}
}

func TestCollectGCP_Preempted(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/id#Metadata-Flavor=Google":        []byte("1234567890"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/preempted#Metadata-Flavor=Google": []byte("TRUE"),
	}, nil, nil)
	var info models.CloudInfo
	if !collectGCP(context.Background(), &info) {
		t.Fatal("expected collectGCP to succeed")
	}
	if !info.SpotTermination {
		t.Error("preempted=TRUE, expected SpotTermination=true")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason explaining the preemption")
	}
}

// ── collectOCI ────────────────────────────────────────────────────────────────

func TestCollectOCI_Success(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/opc/v2/instance/#Authorization=Bearer Oracle": []byte(`{"id":"ocid1.instance.oc1..abc","shape":"VM.Standard.E4.Flex","canonicalRegionName":"us-ashburn-1"}`),
	}, nil, nil)
	var info models.CloudInfo
	if !collectOCI(context.Background(), &info) {
		t.Fatal("expected collectOCI to succeed")
	}
	if info.Provider != "oci" || info.InstanceID != "ocid1.instance.oc1..abc" || info.InstanceType != "VM.Standard.E4.Flex" || info.Region != "us-ashburn-1" {
		t.Errorf("info = %+v, want oci/ocid1.instance.oc1..abc/VM.Standard.E4.Flex/us-ashburn-1", info)
	}
}

func TestCollectOCI_NotAvailable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	var info models.CloudInfo
	if collectOCI(context.Background(), &info) {
		t.Error("expected collectOCI to fail when IMDS is unreachable")
	}
}

// ── IsCloudInstance ───────────────────────────────────────────────────────────

func TestIsCloudInstance_AWS(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok"),
		"imds/http://169.254.169.254/latest/meta-data/instance-id#X-aws-ec2-metadata-token=tok": []byte("i-abc"),
	}, nil, nil)
	if !IsCloudInstance() {
		t.Error("expected IsCloudInstance()=true when the AWS instance-id probe succeeds")
	}
}

// TestIsCloudInstance_AWSIMDSv2TokenRequired is a regression guard for
// internal-collectors-04-01: the old probe sent an empty IMDSv2 token, which
// any AWS instance with IMDSv2 HttpTokens:required enforced rejects with
// HTTP 401 — silently treated as not-cloud. Seeding only the (successful)
// token exchange plus the instance-id GET, with no fallback, must still
// detect AWS.
func TestIsCloudInstance_AWSIMDSv2TokenRequired(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token": []byte("real-token"),
		"imds/http://169.254.169.254/latest/meta-data/instance-id#X-aws-ec2-metadata-token=real-token": []byte("i-abc"),
	}, nil, nil)
	if !IsCloudInstance() {
		t.Error("expected IsCloudInstance()=true when the real IMDSv2 token flow succeeds")
	}
}

func TestIsCloudInstance_GCP(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/id#Metadata-Flavor=Google": []byte("1234567890"),
	}, nil, nil)
	if !IsCloudInstance() {
		t.Error("expected IsCloudInstance()=true when the GCP instance/id probe succeeds")
	}
}

// TestIsCloudInstance_Azure is a regression guard for internal-collectors-04-01:
// Azure was never probed at all — CloudMetaCollector (including Scheduled
// Events maintenance/eviction warnings) was silently never registered on any
// Azure host.
func TestIsCloudInstance_Azure(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/metadata/instance?api-version=2021-02-01#Metadata=true": []byte(`{"compute":{"azEnvironment":"AzurePublicCloud"}}`),
	}, nil, nil)
	if !IsCloudInstance() {
		t.Error("expected IsCloudInstance()=true when the Azure instance-metadata probe succeeds")
	}
}

// TestIsCloudInstance_OCI is a regression guard for internal-collectors-04-01:
// OCI was never probed at all, for the same reason as Azure above.
func TestIsCloudInstance_OCI(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/opc/v2/instance/#Authorization=Bearer Oracle": []byte(`{"id":"ocid1.instance.oc1..abc"}`),
	}, nil, nil)
	if !IsCloudInstance() {
		t.Error("expected IsCloudInstance()=true when the OCI instance probe succeeds")
	}
}

func TestIsCloudInstance_None(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if IsCloudInstance() {
		t.Error("expected IsCloudInstance()=false when no provider probe succeeds")
	}
}
