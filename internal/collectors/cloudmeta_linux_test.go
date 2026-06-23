//go:build linux

package collectors

import (
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
