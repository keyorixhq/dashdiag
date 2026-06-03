package analysis

import (
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
