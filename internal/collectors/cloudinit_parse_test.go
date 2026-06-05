//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestParseCloudInitJSON_Done(t *testing.T) {
	out := `{
		"boot_status_code": "enabled-by-generator",
		"datasource": "nocloud",
		"errors": [],
		"recoverable_errors": {},
		"extended_status": "done",
		"status": "done",
		"last_update": "Thu, 05 Jun 2026 10:00:00 +0000"
	}`
	var info models.CloudInitInfo
	if !parseCloudInitJSON(out, &info) {
		t.Fatal("expected parse to succeed")
	}
	if info.Status != "done" {
		t.Errorf("status = %q, want done", info.Status)
	}
	if info.Datasource != "nocloud" {
		t.Errorf("datasource = %q, want nocloud", info.Datasource)
	}
	if len(info.Errors) != 0 {
		t.Errorf("errors = %v, want none", info.Errors)
	}
}

func TestParseCloudInitJSON_Error(t *testing.T) {
	out := `{
		"datasource": "ec2",
		"errors": ["('modules-config', ...)", "failed to run module foo"],
		"recoverable_errors": {},
		"status": "error"
	}`
	var info models.CloudInitInfo
	if !parseCloudInitJSON(out, &info) {
		t.Fatal("expected parse to succeed")
	}
	if info.Status != "error" {
		t.Errorf("status = %q, want error", info.Status)
	}
	if len(info.Errors) != 2 {
		t.Fatalf("errors len = %d, want 2", len(info.Errors))
	}
}

func TestParseCloudInitJSON_Degraded(t *testing.T) {
	out := `{
		"datasource": "openstack",
		"errors": [],
		"recoverable_errors": {"WARNING": ["disk resize skipped", "no network config"]},
		"extended_status": "degraded done",
		"status": "done"
	}`
	var info models.CloudInitInfo
	if !parseCloudInitJSON(out, &info) {
		t.Fatal("expected parse to succeed")
	}
	if info.ExtendedStatus != "degraded done" {
		t.Errorf("extended_status = %q", info.ExtendedStatus)
	}
	if len(info.RecoverableErrors) != 2 {
		t.Fatalf("recoverable len = %d, want 2", len(info.RecoverableErrors))
	}
	// flattened as "LEVEL: msg"
	if info.RecoverableErrors[0] != "WARNING: disk resize skipped" {
		t.Errorf("recoverable[0] = %q", info.RecoverableErrors[0])
	}
}

func TestParseCloudInitJSON_Garbage(t *testing.T) {
	var info models.CloudInitInfo
	if parseCloudInitJSON("not json at all", &info) {
		t.Error("expected parse to fail on non-JSON")
	}
}

func TestParseCloudInitText_Fallback(t *testing.T) {
	txt := "status: running\n"
	var info models.CloudInitInfo
	parseCloudInitText(txt, &info)
	if info.Status != "running" {
		t.Errorf("status = %q, want running", info.Status)
	}
}

func TestFlattenRecoverable_Ordered(t *testing.T) {
	m := map[string][]string{
		"WARNING": {"w1"},
		"ERROR":   {"e1", "e2"},
	}
	got := flattenRecoverable(m)
	// sorted by level: ERROR before WARNING
	want := []string{"ERROR: e1", "ERROR: e2", "WARNING: w1"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
