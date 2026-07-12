package cmd

import (
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Pure-function tests for small generic/extraction helpers scattered across
// diagnostic.go, explain.go, health.go, migrate.go, and timeline.go.

func TestResultData(t *testing.T) {
	results := []runner.Result{
		{Name: "A", Data: "not it"},
		{Name: "B", Data: &models.DockerInfo{Runtime: "docker"}},
	}
	got := resultData[*models.DockerInfo](results)
	if got == nil || got.Runtime != "docker" {
		t.Errorf("resultData should find the typed result, got %+v", got)
	}
	if got := resultData[*models.MySQLInfo](results); got != nil {
		t.Errorf("no matching type should return the zero value (nil), got %+v", got)
	}
}

func TestFirstErr(t *testing.T) {
	if got := firstErr(nil); got != nil {
		t.Errorf("no results should return nil, got %v", got)
	}
	wantErr := errors.New("collector failed")
	got := firstErr([]runner.Result{{Name: "A"}, {Name: "B", Err: wantErr}})
	if got != wantErr {
		t.Errorf("firstErr should surface the first non-nil error, got %v", got)
	}
}

func TestJSONModeStr(t *testing.T) {
	if got := jsonModeStr(true); got != "json" {
		t.Errorf("jsonModeStr(true) = %q, want json", got)
	}
	if got := jsonModeStr(false); got != "" {
		t.Errorf("jsonModeStr(false) = %q, want empty", got)
	}
}

func TestExtractHealthHelpers(t *testing.T) {
	oomWant := &models.OOMInfo{}
	dockerWant := &models.DockerInfo{Runtime: "podman"}
	results := []runner.Result{
		{Name: "OOM", Data: oomWant},
		{Name: "Docker", Data: dockerWant},
		{Name: "IO", Data: &models.IOInfo{}, Err: errors.New("io failed")}, // errored: must not be extracted
	}
	if got := extractOOM(results); got != oomWant {
		t.Errorf("extractOOM should find the OOM result")
	}
	if got := extractDocker(results); got != dockerWant {
		t.Errorf("extractDocker should find the Docker result")
	}
	if got := extractIO(results); got != nil {
		t.Errorf("an errored IO result must not be extracted as valid data, got %+v", got)
	}
	if got := extractSysctl(results); got != nil {
		t.Errorf("no Sysctl result present should return nil, got %+v", got)
	}
	if got := extractOOM(nil); got != nil {
		t.Errorf("no results at all should return nil for extractOOM, got %+v", got)
	}
	if got := extractDocker([]runner.Result{{Name: "OOM", Data: oomWant}}); got != nil {
		t.Errorf("no Docker result present should return nil, got %+v", got)
	}

	// The found (no-error) match branch — none of the above cases hit it.
	ioWant := &models.IOInfo{}
	sysctlWant := &models.SysctlInfo{}
	found := []runner.Result{
		{Name: "IO", Data: ioWant},
		{Name: "Sysctl", Data: sysctlWant},
	}
	if got := extractIO(found); got != ioWant {
		t.Errorf("extractIO should find a non-errored IO result, got %+v", got)
	}
	if got := extractSysctl(found); got != sysctlWant {
		t.Errorf("extractSysctl should find a non-errored Sysctl result, got %+v", got)
	}
}

func TestExtractCPUAndHealthDeep(t *testing.T) {
	cpuWant := &models.CPUInfo{LoadAvg1: 1.5}
	deepWant := &models.HealthDeepInfo{}
	results := []runner.Result{
		{Name: "CPU Load", Data: cpuWant},
		{Name: "Deep", Data: deepWant},
		{Name: "Bad CPU", Data: &models.CPUInfo{}, Err: errors.New("cpu failed")},
	}
	if got := extractCPU(results); got != cpuWant {
		t.Errorf("extractCPU should find the first non-errored CPUInfo result, got %+v", got)
	}
	if got := extractHealthDeep(results); got != deepWant {
		t.Errorf("extractHealthDeep should find the HealthDeepInfo result, got %+v", got)
	}
	if got := extractCPU(nil); got != nil {
		t.Errorf("no results should return nil, got %+v", got)
	}
	if got := extractHealthDeep([]runner.Result{{Name: "OOM", Data: &models.OOMInfo{}}}); got != nil {
		t.Errorf("no HealthDeepInfo result present should return nil, got %+v", got)
	}
}

func TestTimelineDur(t *testing.T) {
	cases := []struct {
		sec  int64
		want string
	}{
		{45, "45s"},
		{120, "2m"},
		{7320, "2h2m"},
	}
	for _, c := range cases {
		if got := timelineDur(c.sec); got != c.want {
			t.Errorf("timelineDur(%d) = %q, want %q", c.sec, got, c.want)
		}
	}
}

func TestManifestHostAndOS(t *testing.T) {
	named := &source.Bundle{Manifest: source.Manifest{Host: "web01", OS: "Ubuntu 24.04"}}
	if got := manifestHost(named); got != "web01" {
		t.Errorf("manifestHost should return the manifest host, got %q", got)
	}
	if got := manifestOS(named); got != "Ubuntu 24.04" {
		t.Errorf("manifestOS should return the manifest OS, got %q", got)
	}

	empty := &source.Bundle{}
	if got := manifestHost(empty); got != "unknown" {
		t.Errorf("an empty manifest host should fall back to unknown, got %q", got)
	}
	fallbackGOOS := &source.Bundle{Manifest: source.Manifest{GOOS: "linux"}}
	if got := manifestOS(fallbackGOOS); got != "linux" {
		t.Errorf("an empty manifest OS should fall back to GOOS, got %q", got)
	}
}
