//go:build linux

package collectors

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

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
	for i := 0; i < 40; i++ {
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
		"imds/http://169.254.169.254/latest/meta-data/instance-id":      []byte("i-0123456789abcdef0"),
		"imds/http://169.254.169.254/latest/meta-data/instance-type":    []byte("t3.micro"),
		"imds/http://169.254.169.254/latest/meta-data/placement/region": []byte("us-east-1"),
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

// ── collectAWS ────────────────────────────────────────────────────────────────

func TestCollectAWS_Success(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok"),
		"imds/http://169.254.169.254/latest/meta-data/instance-id":      []byte("i-abc"),
		"imds/http://169.254.169.254/latest/meta-data/instance-type":    []byte("m5.large"),
		"imds/http://169.254.169.254/latest/meta-data/placement/region": []byte("eu-west-1"),
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
		"imds/http://169.254.169.254/latest/meta-data/instance-id": []byte("i-abc"),
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
		"imds/http://169.254.169.254/latest/meta-data/instance-id": []byte("i-abc"),
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
		"imds/http://169.254.169.254/metadata/instance?api-version=2021-02-01":        []byte(`{"compute":{"azEnvironment":"AzurePublicCloud"}}`),
		"imds/http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01": []byte(`{"Events":[]}`),
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
		"imds/http://169.254.169.254/metadata/instance?api-version=2021-02-01": []byte(`{"unrelated":"body"}`),
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
		"imds/http://169.254.169.254/metadata/instance?api-version=2021-02-01":        []byte(`{"compute":{"azEnvironment":"AzurePublicCloud"}}`),
		"imds/http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01": []byte(`{"Events":[{"EventType":"Reboot","EventStatus":"Scheduled"}]}`),
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
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/id":           []byte("1234567890"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/machine-type": []byte("n1-standard-1"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/zone":         []byte("us-central1-a"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/preempted":    []byte("FALSE"),
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
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/id":        []byte("1234567890"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/preempted": []byte("TRUE"),
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
		"imds/http://169.254.169.254/opc/v2/instance/": []byte(`{"id":"ocid1.instance.oc1..abc","shape":"VM.Standard.E4.Flex","canonicalRegionName":"us-ashburn-1"}`),
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
		"imds/http://169.254.169.254/latest/meta-data/instance-id": []byte("i-abc"),
	}, nil, nil)
	if !IsCloudInstance() {
		t.Error("expected IsCloudInstance()=true when the AWS instance-id probe succeeds")
	}
}

func TestIsCloudInstance_GCP(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/id": []byte("1234567890"),
	}, nil, nil)
	if !IsCloudInstance() {
		t.Error("expected IsCloudInstance()=true when the GCP instance/id probe succeeds")
	}
}

func TestIsCloudInstance_None(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if IsCloudInstance() {
		t.Error("expected IsCloudInstance()=false when no provider probe succeeds")
	}
}
