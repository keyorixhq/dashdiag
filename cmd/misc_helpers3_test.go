package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestOutputJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := outputJSON(&buf, map[string]int{"a": 1}); err != nil {
		t.Fatalf("outputJSON failed: %v", err)
	}
	if !strings.Contains(buf.String(), `"a": 1`) {
		t.Errorf("outputJSON should indent-encode the value, got:\n%s", buf.String())
	}
}

func TestPrintLogsJSONAndPVEJSON(t *testing.T) {
	logsOut := captureStdout(t, func() { printLogsJSON(&models.LogsInfo{}) })
	if !strings.Contains(logsOut, "{") {
		t.Errorf("printLogsJSON should emit JSON to stdout, got:\n%s", logsOut)
	}

	pveOut := captureStdout(t, func() { _ = printPVEJSON(&models.PVEInfo{ClusterName: "prod"}) })
	if !strings.Contains(pveOut, "prod") {
		t.Errorf("printPVEJSON should emit the info as JSON to stdout, got:\n%s", pveOut)
	}
}

func TestMockInlineFunc(t *testing.T) {
	f := mockInlineFunc([]MockRow{{Name: "CPU", Inline: "12% used"}})
	if got := f("CPU"); got != "12% used" {
		t.Errorf("mockInlineFunc should return the row's inline text, got %q", got)
	}
	if got := f("Unknown"); got != "" {
		t.Errorf("an unknown row name should return empty, got %q", got)
	}
}
