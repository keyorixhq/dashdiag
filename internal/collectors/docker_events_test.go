//go:build linux || darwin

package collectors

import (
	"fmt"
	"strings"
	"testing"
)

// The 10-event display cap must NOT bound OOM counting. On a host with a crash
// storm (>10 die/kill events in the window), an `oom` later in the stream was
// previously dropped because the loop broke after 10 events — silently losing the
// OOM CRIT. parseDockerEvents must count every OOM while still capping the
// display list at 10.
func TestParseDockerEvents_OOMAfterDisplayCap(t *testing.T) {
	var b strings.Builder
	for i := range 11 { // 11 ordinary die events (exit 1, not OOM)
		fmt.Fprintf(&b, `{"Action":"die","Actor":{"Attributes":{"name":"c%d","exitCode":"1"}},"time":%d}`+"\n", i, 1000+i)
	}
	// The OOM kill arrives as the 12th event — past the display cap.
	b.WriteString(`{"Action":"oom","Actor":{"Attributes":{"name":"victim"}},"time":2000}` + "\n")

	events, oom := parseDockerEvents([]byte(b.String()))

	if oom != 1 {
		t.Errorf("oomCount = %d, want 1 (OOM after the 10-event cap must still count)", oom)
	}
	if len(events) != 10 {
		t.Errorf("len(events) = %d, want 10 (display list capped)", len(events))
	}
}

// Podman encodes an OOM kill as a "die" event with exitCode 137.
func TestParseDockerEvents_PodmanOOMAsDie137(t *testing.T) {
	stream := `{"Action":"die","Actor":{"Attributes":{"name":"a","exitCode":"137"}},"time":1}` + "\n" +
		`{"Action":"die","Actor":{"Attributes":{"containerExitCode":"137","name":"b"}},"time":2}` + "\n" +
		`{"Action":"die","Actor":{"Attributes":{"name":"c","exitCode":"0"}},"time":3}`

	_, oom := parseDockerEvents([]byte(stream))
	if oom != 2 {
		t.Errorf("oomCount = %d, want 2 (two die/137, one clean die ignored)", oom)
	}
}

func TestParseDockerEvents_EmptyAndGarbage(t *testing.T) {
	events, oom := parseDockerEvents([]byte("\n  \nnot json\n"))
	if len(events) != 0 || oom != 0 {
		t.Errorf("empty/garbage stream: events=%d oom=%d, want 0/0", len(events), oom)
	}
}

// TestParseDockerEvents_EmbeddedBlankLineSkipped guards the mid-stream empty-
// line skip: a blank line between two real events must be ignored rather than
// producing a spurious parse attempt.
func TestParseDockerEvents_EmbeddedBlankLineSkipped(t *testing.T) {
	stream := `{"Action":"die","Actor":{"Attributes":{"name":"a","exitCode":"1"}},"time":1}` + "\n" +
		"\n" +
		`{"Action":"die","Actor":{"Attributes":{"name":"b","exitCode":"1"}},"time":2}`
	events, oom := parseDockerEvents([]byte(stream))
	if len(events) != 2 || oom != 0 {
		t.Errorf("events=%d oom=%d, want 2/0 (embedded blank line skipped, not parsed as an event)", len(events), oom)
	}
}

// TestParseDockerEvents_ContainerNameFallback guards the Podman attribute-name
// fallback: some events carry the actor name under "containerName" rather than
// "name".
func TestParseDockerEvents_ContainerNameFallback(t *testing.T) {
	stream := `{"Action":"die","Actor":{"Attributes":{"containerName":"fallback-actor","exitCode":"1"}},"time":1}`
	events, _ := parseDockerEvents([]byte(stream))
	if len(events) != 1 || events[0].Actor != "fallback-actor" {
		t.Errorf("events = %+v, want a single event with Actor=fallback-actor", events)
	}
}
