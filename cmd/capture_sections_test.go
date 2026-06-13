package cmd

// capture_sections_test.go — verifies dsd capture --cve / --timeline fold
// standalone report JSON into the fixture, dsd mock replays it through the
// real print funcs, strict validation rejects cross-fed/garbage files, and
// fixtures without these sections replay unchanged (backward compat).

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const cveAllJSON = `{"package_manager":"dnf","total":2,` +
	`"critical":[{"id":"RHSA-2025:1234","cves":"CVE-2025-0001","severity":"Critical","summary":"kernel: privesc"}],` +
	`"fix_command":"dnf update --security"}`

const timelineJSON = `{"window_hours":6,` +
	`"events":[{"timestamp_unix":1717400000,"time_str":"14:13:20","source":"kernel","level":"CRIT","unit":"oom","message":"Out of memory","count":1}],` +
	`"crit_count":1,"warn_count":0}`

func TestStrictUnmarshal_AcceptsRealCVE(t *testing.T) {
	if err := strictUnmarshal([]byte(cveAllJSON), &models.CVEAllResult{}); err != nil {
		t.Fatalf("real cve --all --json rejected by strict validate: %v", err)
	}
}

func TestStrictUnmarshal_AcceptsRealTimeline(t *testing.T) {
	if err := strictUnmarshal([]byte(timelineJSON), &models.TimelineInfo{}); err != nil {
		t.Fatalf("real timeline --json rejected by strict validate: %v", err)
	}
}

func TestStrictUnmarshal_RejectsCrossFed(t *testing.T) {
	// Timeline JSON fed to the CVE validator must fail — the two top-level
	// models share no field names, so window_hours is an unknown field.
	if err := strictUnmarshal([]byte(timelineJSON), &models.CVEAllResult{}); err == nil {
		t.Fatal("timeline JSON accepted as CVEAllResult — strict validation too loose")
	}
	// And the reverse.
	if err := strictUnmarshal([]byte(cveAllJSON), &models.TimelineInfo{}); err == nil {
		t.Fatal("cve JSON accepted as TimelineInfo — strict validation too loose")
	}
}

func TestStrictUnmarshal_RejectsGarbage(t *testing.T) {
	if err := strictUnmarshal([]byte("not json at all"), &models.TimelineInfo{}); err == nil {
		t.Fatal("garbage accepted by strict validate")
	}
}

func TestMockReplayCVE_DecodesValid(t *testing.T) {
	// Valid section decodes and renders without error.
	if err := mockReplayCVE(cveAllJSON); err != nil {
		t.Fatalf("mockReplayCVE failed on valid section: %v", err)
	}
}

func TestMockReplayCVE_EmptyIsNoop(t *testing.T) {
	// Absent section (empty string) must be a no-op, not an error —
	// this is the backward-compat path for fixtures without a cve section.
	if err := mockReplayCVE(""); err != nil {
		t.Fatalf("mockReplayCVE on empty string should be no-op, got: %v", err)
	}
}

func TestMockReplayCVE_MalformedErrors(t *testing.T) {
	if err := mockReplayCVE("{bad json"); err == nil {
		t.Fatal("mockReplayCVE accepted malformed JSON")
	}
}

func TestMockReplayTimeline_DecodesValid(t *testing.T) {
	if err := mockReplayTimeline(timelineJSON); err != nil {
		t.Fatalf("mockReplayTimeline failed on valid section: %v", err)
	}
}

func TestMockReplayTimeline_EmptyIsNoop(t *testing.T) {
	if err := mockReplayTimeline(""); err != nil {
		t.Fatalf("mockReplayTimeline on empty string should be no-op, got: %v", err)
	}
}

func TestMockReplayTimeline_MalformedErrors(t *testing.T) {
	if err := mockReplayTimeline("{bad json"); err == nil {
		t.Fatal("mockReplayTimeline accepted malformed JSON")
	}
}

// captureHost redacts the real hostname by default (fixtures are often committed),
// and only passes it through when --include-identity is set.
func TestCaptureHostRedaction(t *testing.T) {
	if got := captureHost("prod-db-07.internal.example", false); got != "redacted-host" {
		t.Errorf("default must redact hostname, got %q", got)
	}
	if got := captureHost("192.168.1.145", false); got != "redacted-host" {
		t.Errorf("default must redact an IP-style hostname, got %q", got)
	}
	if got := captureHost("prod-db-07", true); got != "prod-db-07" {
		t.Errorf("--include-identity must keep the hostname, got %q", got)
	}
}
