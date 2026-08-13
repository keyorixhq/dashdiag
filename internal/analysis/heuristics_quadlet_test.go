package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A failed Podman quadlet must surface as a WARN naming the failed unit.
func TestCheckPodmanQuadletsFailed(t *testing.T) {
	d := models.DockerInfo{
		Available: true,
		Runtime:   "podman",
		PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "test-nginx", ServiceUnit: "test-nginx.service", Failed: true, State: "failed"},
			{Name: "myapp", ServiceUnit: "myapp.service", Active: true, State: "active"},
		},
	}
	insights := checkPodmanQuadlets(d)
	if len(insights) != 1 {
		t.Fatalf("expected 1 insight, got %d: %+v", len(insights), insights)
	}
	if insights[0].Level != "WARN" {
		t.Errorf("level = %q, want WARN", insights[0].Level)
	}
	if !hasInsight(insights, "WARN", "test-nginx") {
		t.Errorf("WARN should name the failed quadlet test-nginx: %q", insights[0].Message)
	}
	if !hasInsight(insights, "WARN", "1 Podman quadlet(s) failed") {
		t.Errorf("WARN should report the failed count: %q", insights[0].Message)
	}
}

// Zero failed quadlets → no insight (no noise), even with active quadlets present.
func TestCheckPodmanQuadletsAllActive(t *testing.T) {
	d := models.DockerInfo{
		Available: true,
		Runtime:   "podman",
		PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "test-nginx", ServiceUnit: "test-nginx.service", Active: true, State: "active"},
			{Name: "myapp", ServiceUnit: "myapp.service", Active: true, State: "active"},
		},
	}
	if got := checkPodmanQuadlets(d); got != nil {
		t.Errorf("expected no insight for all-active quadlets, got %+v", got)
	}
}

// No quadlets at all (Docker host or none defined) → no insight.
func TestCheckPodmanQuadletsNone(t *testing.T) {
	d := models.DockerInfo{Available: true, Runtime: "docker"}
	if got := checkPodmanQuadlets(d); got != nil {
		t.Errorf("expected no insight when no quadlets present, got %+v", got)
	}
}

// Multiple failed quadlets are all named in a single WARN.
func TestCheckPodmanQuadletsMultipleFailed(t *testing.T) {
	d := models.DockerInfo{
		Available: true,
		Runtime:   "podman",
		PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "a", ServiceUnit: "a.service", Failed: true, State: "failed"},
			{Name: "b", ServiceUnit: "b.service", Failed: true, State: "failed"},
		},
	}
	insights := checkPodmanQuadlets(d)
	if len(insights) != 1 {
		t.Fatalf("expected 1 insight, got %d", len(insights))
	}
	if !hasInsight(insights, "WARN", "2 Podman quadlet(s) failed") {
		t.Errorf("want failed count 2: %q", insights[0].Message)
	}
	if !hasInsight(insights, "WARN", "a, b") {
		t.Errorf("want both names: %q", insights[0].Message)
	}
}

// TestCheckPodmanQuadletsFailedCapAt3 is the regression test for
// internal-analysis-12-04: checkPodmanQuadlets joined the full, uncapped
// failed/inactive/unverified name lists into the insight message, unlike
// every sibling list-formatting call in this file (checkKVMVMs,
// checkDockerContainers, checkK8sWorkloadsAndEvents, ...), which all cap with
// firstN(names, 3). A host with many failed quadlets must not produce an
// unbounded message.
func TestCheckPodmanQuadletsFailedCapAt3(t *testing.T) {
	d := models.DockerInfo{
		Available: true,
		Runtime:   "podman",
		PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "a", ServiceUnit: "a.service", Failed: true, State: "failed"},
			{Name: "b", ServiceUnit: "b.service", Failed: true, State: "failed"},
			{Name: "c", ServiceUnit: "c.service", Failed: true, State: "failed"},
			{Name: "d", ServiceUnit: "d.service", Failed: true, State: "failed"},
			{Name: "e", ServiceUnit: "e.service", Failed: true, State: "failed"},
		},
	}
	insights := checkPodmanQuadlets(d)
	if len(insights) != 1 {
		t.Fatalf("expected 1 insight, got %d", len(insights))
	}
	if !hasInsight(insights, "WARN", "5 Podman quadlet(s) failed") {
		t.Errorf("want failed count 5: %q", insights[0].Message)
	}
	if !strings.Contains(insights[0].Message, "a, b, c") {
		t.Errorf("want the first 3 names joined: %q", insights[0].Message)
	}
	if strings.Contains(insights[0].Message, "a, b, c, d") {
		t.Errorf("failed quadlet names must be capped at 3 (like every other list in this file), got %q", insights[0].Message)
	}
}

// FALSE_OK_SWEEP #34: a quadlet whose state couldn't be read (systemctl errored,
// State="") must surface as INFO "could not determine", not a silent OK.
func TestCheckPodmanQuadletsUnverified(t *testing.T) {
	d := models.DockerInfo{
		Available: true, Runtime: "podman",
		PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "mystery", ServiceUnit: "mystery.service", State: ""},
		},
	}
	got := checkPodmanQuadlets(d)
	if !hasInsight(got, "INFO", "could not determine state") || !hasInsight(got, "INFO", "mystery") {
		t.Errorf("unreadable quadlet must INFO naming it, got %+v", got)
	}
}

// A quadlet file present but its unit inactive (stopped / unit-name mismatch) →
// WARN "present but not active", not a silent OK.
func TestCheckPodmanQuadletsInactive(t *testing.T) {
	d := models.DockerInfo{
		Available: true, Runtime: "podman",
		PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "down", ServiceUnit: "down.service", State: "inactive"},
		},
	}
	if got := checkPodmanQuadlets(d); !hasInsight(got, "WARN", "present but not active") {
		t.Errorf("inactive quadlet must WARN, got %+v", got)
	}
}

// Transient states (activating) are NOT flagged — avoids boot-time false alarms.
func TestCheckPodmanQuadletsTransientSilent(t *testing.T) {
	d := models.DockerInfo{
		Available: true, Runtime: "podman",
		PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "booting", ServiceUnit: "booting.service", State: "activating"},
		},
	}
	if got := checkPodmanQuadlets(d); got != nil {
		t.Errorf("transient activating quadlet must be silent, got %+v", got)
	}
}
