//go:build linux

package collectors

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

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
	return info, nil
}

// imdsGet caches imdsGetLive through the source so cloud metadata replays from the
// bundle instead of re-querying the live IMDS endpoint (which is absent/different on
// a replay box). Keyed by URL — each metadata field is fetched once.
func imdsGet(ctx context.Context, url string, headers map[string]string) (string, error) {
	data, err := activeSource.Cached("imds/"+url, func() ([]byte, error) {
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

func imdsGetLive(ctx context.Context, url string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return strings.TrimSpace(string(buf[:n])), nil
}

func collectAWS(ctx context.Context, info *models.CloudInfo) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	// IMDSv2 requires a token first. Cached so the live token PUT replays from the
	// bundle — otherwise replay fails here (no IMDS on the replay box) before the
	// cached metadata GETs are ever reached.
	token, err := awsIMDSToken(ctx, client)
	if err != nil {
		return false
	}

	headers := map[string]string{"X-aws-ec2-metadata-token": token}

	iid, err := imdsGet(ctx, "http://169.254.169.254/latest/meta-data/instance-id", headers)
	if err != nil || iid == "" {
		return false
	}

	info.Available = true
	info.Provider = "aws"
	info.InstanceID = iid
	info.InstanceType, _ = imdsGet(ctx, "http://169.254.169.254/latest/meta-data/instance-type", headers)
	info.Region, _ = imdsGet(ctx, "http://169.254.169.254/latest/meta-data/placement/region", headers)

	// Spot termination notice — 200 means termination imminent. Cached.
	var spotTerm bool
	_ = cachedJSON("imds-aws-termination", func() (any, error) {
		return awsSpotTerminationLive(ctx, client, token), nil
	}, &spotTerm)
	if spotTerm {
		info.SpotTermination = true
		info.StatusReason = "spot instance scheduled for termination"
	}

	return true
}

// awsIMDSToken fetches (and caches) an IMDSv2 session token. The token value is
// only used as a request header for the metadata GETs, which are themselves cached
// by URL — so on replay the recorded token simply lets collectAWS proceed past the
// gate; its exact value is immaterial.
func awsIMDSToken(ctx context.Context, client *http.Client) (string, error) {
	data, err := activeSource.Cached("imds-aws-token", func() ([]byte, error) {
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
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		return buf[:n], nil
	})
	return string(data), err
}

// awsSpotTerminationLive reports whether a spot-termination notice is posted
// (HTTP 200 on the termination-time endpoint).
func awsSpotTerminationLive(ctx context.Context, client *http.Client, token string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/latest/meta-data/spot/termination-time", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close() //nolint:errcheck
	return resp.StatusCode == 200
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

	// Azure scheduled events for maintenance
	events, err := imdsGet(ctx,
		"http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01",
		map[string]string{"Metadata": "true"})
	if err == nil && strings.Contains(events, "Freeze") || strings.Contains(events, "Reboot") {
		info.MaintenanceEvent = true
		info.MaintenanceDetails = "Azure scheduled maintenance event pending"
	}
	return true
}

func collectGCP(ctx context.Context, info *models.CloudInfo) bool {
	iid, err := imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/id",
		map[string]string{"Metadata-Flavor": "Google"})
	if err != nil || iid == "" {
		return false
	}
	info.Available = true
	info.Provider = "gcp"
	info.InstanceID = iid
	info.InstanceType, _ = imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/machine-type",
		map[string]string{"Metadata-Flavor": "Google"})
	info.Region, _ = imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/zone",
		map[string]string{"Metadata-Flavor": "Google"})

	// Preemptible termination notice
	preempt, err := imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/preempted",
		map[string]string{"Metadata-Flavor": "Google"})
	if err == nil && strings.TrimSpace(preempt) == "TRUE" {
		info.SpotTermination = true
		info.StatusReason = "GCP preemptible instance scheduled for termination"
	}
	return true
}

// IsCloudInstance returns true if running on a known cloud provider.
func IsCloudInstance() bool {
	// Quick check: try AWS and GCP metadata endpoints with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := imdsGet(ctx, "http://169.254.169.254/latest/meta-data/instance-id",
		map[string]string{"X-aws-ec2-metadata-token": ""})
	if err == nil {
		return true
	}
	_, err = imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/id",
		map[string]string{"Metadata-Flavor": "Google"})
	return err == nil
}
