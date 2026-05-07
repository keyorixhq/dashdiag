package collectors

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

func TestParseLoadAvg(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		input      string
		wantLoad1  float64
		wantLoad5  float64
		wantLoad15 float64
		wantErr    bool
	}{
		{"healthy", "0.52 0.43 0.32 3/412 8932", 0.52, 0.43, 0.32, false},
		{"zero load", "0.00 0.00 0.00 1/100 1234", 0.0, 0.0, 0.0, false},
		{"high load", "15.20 12.80 10.50 8/412 9999", 15.20, 12.80, 10.50, false},
		{"malformed", "garbage", 0, 0, 0, true},
		{"empty", "", 0, 0, 0, true},
		{"two fields only", "1.0 2.0", 0, 0, 0, true},
		{"non-numeric", "a b c 1/2 3", 0, 0, 0, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l1, l5, l15, err := parseLoadAvg(strings.NewReader(tc.input))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if l1 != tc.wantLoad1 {
				t.Errorf("load1: got %v, want %v", l1, tc.wantLoad1)
			}
			if l5 != tc.wantLoad5 {
				t.Errorf("load5: got %v, want %v", l5, tc.wantLoad5)
			}
			if l15 != tc.wantLoad15 {
				t.Errorf("load15: got %v, want %v", l15, tc.wantLoad15)
			}
		})
	}
}

func FuzzParseLoadAvg(f *testing.F) {
	f.Add("0.52 0.43 0.32 3/412 8932")
	f.Add("garbage")
	f.Add("")
	f.Add("0.00 0.00 0.00 1/100 1234")
	f.Fuzz(func(t *testing.T, s string) {
		parseLoadAvg(strings.NewReader(s)) //nolint:errcheck
	})
}

func TestParseCPUStat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		input     string
		wantIdle  uint64
		wantTotal uint64
		wantErr   bool
	}{
		{
			name:      "healthy linux stat",
			input:     "cpu  100 20 30 800 10 0 5 0 0 0\n",
			wantIdle:  800,
			wantTotal: 965,
		},
		{
			name:      "minimal fields",
			input:     "cpu  1 2 3 4 5\n",
			wantIdle:  4,
			wantTotal: 15,
		},
		{
			name:    "no cpu line",
			input:   "cpu0 1 2 3 4 5\ncpu1 6 7 8 9 10\n",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "cpu line too short",
			input:   "cpu  1 2 3\n",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			idle, total, err := parseCPUStat(strings.NewReader(tc.input))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if idle != tc.wantIdle {
				t.Errorf("idle: got %v, want %v", idle, tc.wantIdle)
			}
			if total != tc.wantTotal {
				t.Errorf("total: got %v, want %v", total, tc.wantTotal)
			}
		})
	}
}

func TestCPUCollector_Collect_InjectableReaders(t *testing.T) {
	t.Parallel()

	loadAvgContent := "1.50 1.20 0.90 3/412 8932"
	// idle delta=100, total delta=200 → usage = (1 - 100/200)*100 = 50%
	stat1 := "cpu  100 20 30 400 10 0 5 0 0 0\n"
	stat2 := "cpu  200 20 30 500 10 0 5 0 0 0\n"

	callCount := 0
	c := &CPUCollector{
		ContainerCtx: platform.ContainerContext{},
		readers: cpuReaders{
			loadAvgOpen: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(loadAvgContent)), nil
			},
			statOpen: func() (io.ReadCloser, error) {
				callCount++
				if callCount == 1 {
					return io.NopCloser(strings.NewReader(stat1)), nil
				}
				return io.NopCloser(strings.NewReader(stat2)), nil
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := result.(*models.CPUInfo)
	if !ok {
		t.Fatalf("unexpected type %T", result)
	}
	if info.LoadAvg1 != 1.50 {
		t.Errorf("LoadAvg1: got %v, want 1.50", info.LoadAvg1)
	}
	// idle delta=100, total delta=200 → usage = (1 - 100/200)*100 = 50%
	if info.UsagePct < 49 || info.UsagePct > 51 {
		t.Errorf("UsagePct: got %v, want ~50%%", info.UsagePct)
	}
}
