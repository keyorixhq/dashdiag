package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestCPUIcon(t *testing.T) {
	cases := []struct {
		name            string
		val, warn, crit float64
		want            string
	}{
		{"below warn", 10, 50, 90, "OK"},
		{"at warn", 50, 50, 90, "WARN"},
		{"between warn and crit", 70, 50, 90, "WARN"},
		{"at crit", 90, 50, 90, "CRIT"},
		{"above crit", 99, 50, 90, "CRIT"},
	}
	for _, c := range cases {
		got := strings.TrimSpace(cpuIcon(c.val, c.warn, c.crit, output.ModePlain))
		if got != c.want {
			t.Errorf("%s: cpuIcon(%v, warn=%v, crit=%v) = %q, want %q", c.name, c.val, c.warn, c.crit, got, c.want)
		}
	}
}

// TestCPUTotalFailureErr is a regression guard for cmd-02-01: runCPU used to
// discard every collector's error and fall through to a fabricated "CPU
// healthy" summary (exit 0) when all four collectors failed. It must now bail
// with a real error — surfacing the underlying collector error when one is
// available, and any single successful collector must NOT trigger the bail
// (thermal/cpufreq are honestly nil-without-error on VMs/containers).
func TestCPUTotalFailureErr(t *testing.T) {
	loadErr := errors.New("load average: permission denied")
	cases := []struct {
		name                               string
		cpuRaw, freqRaw, thermalRaw, hwRaw any
		results                            []runner.Result
		wantErr                            bool
		wantErrIs                          error
	}{
		{
			name: "all nil with an underlying error", wantErr: true, wantErrIs: loadErr,
			results: []runner.Result{{Name: "CPU Load", Err: loadErr}},
		},
		{
			name: "all nil with no underlying error", wantErr: true,
			results: []runner.Result{{Name: "CPU Load"}},
		},
		{
			name: "CPU present, rest nil (thermal/freq honestly absent)", wantErr: false,
			cpuRaw: &models.CPUInfo{}, results: []runner.Result{{Name: "CPU Load", Data: &models.CPUInfo{}}},
		},
		{
			name: "only Hardware present", wantErr: false,
			hwRaw: &models.HardwareInfo{}, results: []runner.Result{{Name: "Hardware", Data: &models.HardwareInfo{}}},
		},
		{
			name: "all four present", wantErr: false,
			cpuRaw: &models.CPUInfo{}, freqRaw: &models.CPUFreqInfo{},
			thermalRaw: &models.ThermalInfo{}, hwRaw: &models.HardwareInfo{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cpuTotalFailureErr(tc.cpuRaw, tc.freqRaw, tc.thermalRaw, tc.hwRaw, tc.results)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("got error %v, want it to wrap %v", err, tc.wantErrIs)
			}
		})
	}
}
