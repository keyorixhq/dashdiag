//go:build linux

package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
