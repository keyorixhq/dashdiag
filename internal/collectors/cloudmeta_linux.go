//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

const (
	cloudMetadataFlavorHeader = "Metadata-Flavor"
	cloudGCPProvider          = "Google"
	cloudAWSTokenHeader       = "X-aws-ec2-metadata-token" //nolint:gosec // HTTP header name, not a credential
)

// imdsMaxBodyBytes caps an IMDS response body. A single fixed-size Read() used
// to silently truncate anything past 4KB — Azure's compute/storageProfile
// document for a multi-data-disk VM (each managedDisk.id is a ~200-char ARM
// resource path) routinely exceeds that, truncating the JSON mid-object and
// making parseAzureStorageProfile fail closed exactly on the multi-disk VMs the
// host-caching-hazard check targets. 1MB is far larger than any real IMDS
// document while still bounding a misbehaving/malicious responder.
const imdsMaxBodyBytes = 1 << 20

// errIMDSNetworkDisallowed is returned by every IMDS call site in this
// package when platform.NetworkAllowed() is false — never a fabricated
// timeout/unreachable error, so a caller logging the error text can tell
// "declined by policy" apart from a genuine probe failure.
var errIMDSNetworkDisallowed = fmt.Errorf("imds: network calls disallowed (see platform.NetworkAllowed)")

// newIMDSHTTPClient returns an http.Client for talking to an instance metadata
// service, with redirect-following disabled. IMDS endpoints never legitimately
// redirect; a real IMDS implementation (AWS/Azure/GCP/OCI) always answers
// requests for its known paths directly. Following a redirect would let a
// compromised/spoofed responder on the link-local address (or a captive
// portal/proxy squatting on it) send the client — including the IMDSv2
// session token carried in X-aws-ec2-metadata-token — to an attacker-chosen
// host. CheckRedirect returning http.ErrUseLastResponse makes Client.Do
// return the redirect response itself (a non-2xx status) instead of
// following it, so callers' existing "non-200 = not metadata" handling
// rejects it for free.
func newIMDSHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type CloudMetaCollector struct{}

func NewCloudMetaCollector() *CloudMetaCollector     { return &CloudMetaCollector{} }
func (c *CloudMetaCollector) Name() string           { return "CloudMeta" }
func (c *CloudMetaCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *CloudMetaCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.CloudInfo{}

	// Try each provider's IMDS endpoint in order.
	// All use link-local addresses that are only routable on the instance.
	if collectAWS(ctx, info) {
		return info, nil
	}
	if collectAzure(ctx, info) {
		return info, nil
	}
	if collectGCP(ctx, info) {
		return info, nil
	}
	if collectOCI(ctx, info) {
		return info, nil
	}
	return info, nil
}

// imdsGet caches imdsGetLive through the source so cloud metadata replays from the
// bundle instead of re-querying the live IMDS endpoint (which is absent/different on
// a replay box). Keyed by URL AND headers.
//
// internal-collectors-04-02: keying by URL alone meant two calls to the same URL with
// DIFFERENT headers (different auth tokens/contexts) collided — the second call
// silently got the first's cached response instead of its own. imdsCacheKey folds a
// deterministic, sorted encoding of the headers into the key so differing headers for
// the same URL never collide, while identical (url, headers) pairs still hit the same
// cache entry as before.
func imdsGet(ctx context.Context, url string, headers map[string]string) (string, error) {
	// gap B was closed for checkIMDS (platform/cloud.go) but missed every
	// collector in this file — this is the low-level choke point all of them
	// route through, so gating it here closes AWS/Azure/GCP/OCI in one place.
	// sourceIsReplaying short-circuits the gate under `dsd replay`: a bundle
	// captured before this fix must still replay its recorded IMDS responses,
	// never fabricate "skipped" over them.
	if !platform.NetworkAllowed() && !sourceIsReplaying() {
		return "", errIMDSNetworkDisallowed
	}
	data, err := curSource().Cached(imdsCacheKey(url, headers), func() ([]byte, error) {
		s, e := imdsGetLive(ctx, url, headers)
		if e != nil {
			return nil, e
		}
		return []byte(s), nil
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// imdsCacheKey builds imdsGet's Cached() key: "imds/"+url, plus a "#"-delimited,
// sorted "K=V&K=V" suffix when headers are present. Headers are sorted by name first
// — map iteration order is random in Go, and an unsorted encoding would make the same
// logical request hash to a different key across calls, defeating the cache instead of
// just protecting it. "#" (not "?") is the separator so this never collides with a
// query string some IMDS URLs already carry (e.g. Azure's
// ".../storageProfile?api-version=...&format=json").
func imdsCacheKey(url string, headers map[string]string) string {
	key := "imds/" + url
	if len(headers) == 0 {
		return key
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(key)
	b.WriteByte('#')
	for i, k := range names {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(headers[k])
	}
	return b.String()
}

func imdsGetLive(ctx context.Context, url string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := newIMDSHTTPClient(2 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// A non-2xx response (404 for an absent key, 403, a captive-portal/proxy page,
	// a redirect) is NOT metadata. Returning its body as a value made callers treat
	// an error page as the field — e.g. GCP's maintenance-event check false-WARNed
	// on any non-"NONE" error body, and the on-host-maintenance check recorded
	// checked=true with a garbage policy (false-OK). Fail closed so callers degrade
	// to "couldn't verify" instead.
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("imds %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, imdsMaxBodyBytes))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func collectAWS(ctx context.Context, info *models.CloudInfo) bool {
	client := newIMDSHTTPClient(2 * time.Second)
	// IMDSv2 requires a token first. Cached so the live token PUT replays from the
	// bundle — otherwise replay fails here (no IMDS on the replay box) before the
	// cached metadata GETs are ever reached.
	token, err := awsIMDSToken(ctx, client)
	if err != nil {
		return false
	}

	headers := map[string]string{cloudAWSTokenHeader: token}

	iid, err := imdsGet(ctx, "http://169.254.169.254/latest/meta-data/instance-id", headers)
	if err != nil || iid == "" {
		return false
	}

	info.Available = true
	info.Provider = "aws"
	info.InstanceID = iid
	info.InstanceType, _ = imdsGet(ctx, "http://169.254.169.254/latest/meta-data/instance-type", headers)
	info.Region, _ = imdsGet(ctx, "http://169.254.169.254/latest/meta-data/placement/region", headers)

	// Spot termination notice — 200 means termination imminent, 404 means no notice
	// (normal). A transient IMDS error / unexpected status must NOT read as "no
	// termination" — distinguish it so an imminent reclaim isn't hidden. Cached.
	var spot awsSpotStatus
	_ = cachedJSON("imds-aws-termination", func() (any, error) {
		return awsSpotTermination(ctx, client, token), nil
	}, &spot)
	switch {
	case spot.Terminating:
		info.SpotTermination = true
		info.StatusReason = "spot instance scheduled for termination"
	case spot.CheckFailed:
		info.SpotCheckFailed = true
	}

	return true
}

// awsSpotStatus is the result of the spot-termination probe, distinguishing a
// confirmed notice / confirmed-absent (404) from an IMDS error we couldn't resolve.
type awsSpotStatus struct {
	Terminating bool `json:"terminating"`
	CheckFailed bool `json:"check_failed"`
}

// awsIMDSToken fetches (and caches) an IMDSv2 session token. The token value is
// only used as a request header for the metadata GETs, which are themselves cached
// by URL — so on replay the recorded token simply lets collectAWS proceed past the
// gate; its exact value is immaterial.
func awsIMDSToken(ctx context.Context, client *http.Client) (string, error) {
	// Own raw PUT, not routed through imdsGet — gate separately or a
	// network-disallowed run would still leak this one live call before
	// imdsGet's own gate ever gets a chance to block the follow-up GETs.
	if !platform.NetworkAllowed() && !sourceIsReplaying() {
		return "", errIMDSNetworkDisallowed
	}
	data, err := curSource().Cached("imds-aws-token", func() ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodPut,
			"http://169.254.169.254/latest/api/token", nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		resp, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		defer resp.Body.Close() //nolint:errcheck
		// A single fixed-buffer Read() is not guaranteed by the io.Reader
		// contract to return all available bytes in one call (e.g. under
		// chunked transfer-encoding) — a short first read silently truncates
		// the token, corrupting every tokened metadata GET that follows.
		// Match imdsGetLive's ReadAll+LimitReader pattern instead.
		return io.ReadAll(io.LimitReader(resp.Body, imdsMaxBodyBytes))
	})
	return string(data), err
}

// awsSpotTermination probes the spot termination-time endpoint. HTTP 200 = a notice
// is posted (termination imminent); 404 = no notice (the normal case, also on
// on-demand instances); a request error or any other status = couldn't confirm, so
// CheckFailed is set rather than silently reporting "no termination".
func awsSpotTermination(ctx context.Context, client *http.Client, token string) awsSpotStatus {
	// Own raw GET, called from inside collectAWS's cachedJSON closure — gating
	// here (not in collectAWS, before the cachedJSON call) keeps this safe
	// under replay the same way imdsGetLive is: Replay.Cached never invokes
	// the produce closure, so this check only ever fires on a live run.
	if !platform.NetworkAllowed() && !sourceIsReplaying() {
		return awsSpotStatus{CheckFailed: true}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/latest/meta-data/spot/termination-time", nil)
	if err != nil {
		return awsSpotStatus{CheckFailed: true}
	}
	req.Header.Set(cloudAWSTokenHeader, token)
	resp, err := client.Do(req)
	if err != nil {
		return awsSpotStatus{CheckFailed: true}
	}
	defer resp.Body.Close() //nolint:errcheck
	switch resp.StatusCode {
	case 200:
		return awsSpotStatus{Terminating: true}
	case 404:
		return awsSpotStatus{} // no termination scheduled — the normal case
	default:
		return awsSpotStatus{CheckFailed: true} // unexpected status — couldn't confirm
	}
}

func collectAzure(ctx context.Context, info *models.CloudInfo) bool {
	body, err := imdsGet(ctx,
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		map[string]string{"Metadata": "true"})
	if err != nil || body == "" {
		return false
	}
	if !strings.Contains(body, "azEnvironment") {
		return false
	}
	info.Available = true
	info.Provider = "azure"

	// Azure Scheduled Events: pending platform maintenance (freeze/reboot/redeploy) or
	// eviction (preempt/terminate). Parse the JSON properly — the previous string-match
	// had an operator-precedence bug ((err==nil && Freeze) || Reboot) that ignored the
	// IMDS error on the Reboot branch and missed Redeploy/Preempt/Terminate entirely.
	events, err := imdsGet(ctx,
		"http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01",
		map[string]string{"Metadata": "true"})
	if err == nil {
		if pending, details := parseAzureScheduledEvents(events); pending {
			info.MaintenanceEvent = true
			info.MaintenanceDetails = details
		}
	}
	return true
}

// azureScheduledEvents mirrors the IMDS /scheduledevents document.
type azureScheduledEvents struct {
	Events []struct {
		EventType   string `json:"EventType"`   // Freeze / Reboot / Redeploy / Preempt / Terminate
		EventStatus string `json:"EventStatus"` // Scheduled / Started
		NotBefore   string `json:"NotBefore"`
	} `json:"Events"`
}

// parseAzureScheduledEvents reports whether any maintenance/eviction event is pending
// and a human-readable summary. Returns false on empty/garbled bodies so a failed read
// never reads as "event pending".
func parseAzureScheduledEvents(body string) (pending bool, details string) {
	var se azureScheduledEvents
	if err := json.Unmarshal([]byte(body), &se); err != nil || len(se.Events) == 0 {
		return false, ""
	}
	var parts []string
	for _, e := range se.Events {
		if e.EventType == "" {
			continue
		}
		p := e.EventType
		if e.EventStatus != "" {
			p += " (" + e.EventStatus
			if e.NotBefore != "" {
				p += ", not before " + e.NotBefore
			}
			p += ")"
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return false, ""
	}
	return true, strings.Join(parts, "; ")
}

func collectGCP(ctx context.Context, info *models.CloudInfo) bool {
	iid, err := imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/id",
		map[string]string{cloudMetadataFlavorHeader: cloudGCPProvider})
	if err != nil || iid == "" {
		return false
	}
	info.Available = true
	info.Provider = "gcp"
	info.InstanceID = iid
	info.InstanceType, _ = imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/machine-type",
		map[string]string{cloudMetadataFlavorHeader: cloudGCPProvider})
	info.Region, _ = imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/zone",
		map[string]string{cloudMetadataFlavorHeader: cloudGCPProvider})

	// Preemptible termination notice
	preempt, err := imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/preempted",
		map[string]string{cloudMetadataFlavorHeader: cloudGCPProvider})
	if err == nil && strings.TrimSpace(preempt) == "TRUE" {
		info.SpotTermination = true
		info.StatusReason = "GCP preemptible instance scheduled for termination"
	}
	return true
}

func collectOCI(ctx context.Context, info *models.CloudInfo) bool {
	doc := ociInstanceDocRead(ctx)
	if doc == nil || doc.ID == "" {
		return false
	}
	info.Available = true
	info.Provider = "oci"
	info.InstanceID = doc.ID
	info.InstanceType = doc.Shape
	info.Region = doc.CanonicalRegionName
	// OCI has no widely-used preemptible-instance signal comparable to AWS spot /
	// GCP preemptible for general compute shapes — no SpotTermination probe here.
	return true
}

// IsCloudInstance returns true if running on a known cloud provider — the gate
// `dsd health` uses to decide whether to register CloudMetaCollector at all.
//
// internal-collectors-04-01: this used to probe only AWS and GCP (Azure and
// OCI were never checked, so CloudMetaCollector — including Azure Scheduled
// Events maintenance/eviction warnings — was silently never registered on
// those platforms), and its AWS probe sent an empty IMDSv2 token instead of
// performing the real token PUT collectAWS does via awsIMDSToken. Any AWS
// instance with IMDSv2 HttpTokens:required enforced (AWS's own recommended
// hardening default) got HTTP 401 on the token-less GET and was silently
// treated as not-cloud, hiding the spot-termination notice CloudMetaCollector
// would otherwise have caught. Now checks all four providers, each with the
// same minimal presence probe its own collectXXX function relies on.
func IsCloudInstance() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	client := newIMDSHTTPClient(500 * time.Millisecond)
	if token, err := awsIMDSToken(ctx, client); err == nil {
		if _, err := imdsGet(ctx, "http://169.254.169.254/latest/meta-data/instance-id",
			map[string]string{cloudAWSTokenHeader: token}); err == nil {
			return true
		}
	}

	if body, err := imdsGet(ctx,
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		map[string]string{"Metadata": "true"}); err == nil && strings.Contains(body, "azEnvironment") {
		return true
	}

	if _, err := imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/id",
		map[string]string{cloudMetadataFlavorHeader: cloudGCPProvider}); err == nil {
		return true
	}

	_, err := imdsGet(ctx, "http://169.254.169.254/opc/v2/instance/",
		map[string]string{"Authorization": "Bearer Oracle"})
	return err == nil
}
