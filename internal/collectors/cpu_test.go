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

func TestParseCPUStatFullAuxLines(t *testing.T) {
	t.Parallel()
	// Realistic /proc/stat: cpu aggregate, per-cpu lines, then ctxt/procs_* lines.
	input := "cpu  100 20 30 800 10 0 5 0 0 0\n" +
		"cpu0 50 10 15 400 5 0 2 0 0 0\n" +
		"cpu1 50 10 15 400 5 0 3 0 0 0\n" +
		"intr 123456 0 0\n" +
		"ctxt 987654\n" +
		"btime 1700000000\n" +
		"processes 4321\n" +
		"procs_running 7\n" +
		"procs_blocked 3\n" +
		"softirq 555 1 2 3\n"

	s, err := parseCPUStatFull(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.idle != 800 || s.total != 965 {
		t.Errorf("idle/total: got %d/%d, want 800/965", s.idle, s.total)
	}
	if s.ctxt != 987654 {
		t.Errorf("ctxt: got %d, want 987654", s.ctxt)
	}
	if s.procsRunning != 7 {
		t.Errorf("procsRunning: got %d, want 7", s.procsRunning)
	}
	if s.procsBlocked != 3 {
		t.Errorf("procsBlocked: got %d, want 3", s.procsBlocked)
	}
}

func TestParseStatUint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want uint64
	}{
		{"ctxt 123456", 123456},
		{"procs_running 2", 2},
		{"procs_blocked 0", 0},
		{"ctxt", 0},            // no value
		{"ctxt notanumber", 0}, // unparseable
		{"", 0},
	}
	for _, tc := range cases {
		if got := parseStatUint(tc.line); got != tc.want {
			t.Errorf("parseStatUint(%q): got %d, want %d", tc.line, got, tc.want)
		}
	}
}

func TestCPUCollector_Collect_RunQueueFields(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping 500ms CPU sampling in short mode")
	}

	loadAvgContent := "1.50 1.20 0.90 7/412 8932"
	stat1 := "cpu  100 20 30 400 10 0 5 0 0 0\nctxt 1000\nprocs_running 1\nprocs_blocked 0\n"
	stat2 := "cpu  200 20 30 500 10 0 5 0 0 0\nctxt 1500\nprocs_running 9\nprocs_blocked 2\n"

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
	info := result.(*models.CPUInfo) //nolint:errcheck // type asserted in sibling test
	// RunQueue/ProcsBlocked come from the most recent (second) sample.
	if info.RunQueue != 9 {
		t.Errorf("RunQueue: got %d, want 9", info.RunQueue)
	}
	if info.ProcsBlocked != 2 {
		t.Errorf("ProcsBlocked: got %d, want 2", info.ProcsBlocked)
	}
	// ctxt delta 500 over ~0.5s → positive rate.
	if info.ContextSwitchRate <= 0 {
		t.Errorf("ContextSwitchRate: got %v, want > 0", info.ContextSwitchRate)
	}
}

func TestCPUCollector_Collect_InjectableReaders(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping 500ms CPU sampling in short mode")
	}

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

func TestParseSelfCPUJiffies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{
			// comm contains a space AND a ')' — must count fields from the LAST ')'.
			// utime=11 stime=7 cutime=3 cstime=1 → 22
			name:  "comm with space and paren",
			input: "1234 (weird )name) S 1 1234 1234 0 -1 4194560 100 200 0 0 11 7 3 1 0 0 0 20 1",
			want:  22,
		},
		{
			name:  "simple comm",
			input: "42 (dsd) R 1 42 42 0 -1 4194304 50 0 0 0 30 20 0 0 0 0 0 18 1",
			want:  50,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSelfCPUJiffies(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("parseSelfCPUJiffies error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d jiffies, want %d", got, tc.want)
			}
		})
	}
}

// TestCPUCollector_Collect_SelfSubtraction proves dsd excludes its own
// process-tree CPU from the usage figure — the fix for the observer-effect
// false positive where parallel collectors saturate a small-core VM and dsd
// reported its own load as the host's (idle box reading ~95-99% CPU).
func TestCPUCollector_Collect_SelfSubtraction(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping 500ms CPU sampling in short mode")
	}

	loadAvgContent := "1.50 1.20 0.90 3/412 8932"
	// user delta=100, idle delta=100 → total delta=200, raw busy delta=100
	// (50% without subtraction).
	stat1 := "cpu  100 0 0 400 0 0 0 0 0 0\n"
	stat2 := "cpu  200 0 0 500 0 0 0 0 0 0\n"
	// dsd's own CPU over the window: utime+stime+cutime+cstime = 10 → 60, delta=50.
	// adjusted busy = 100 - 50 = 50 → usage = 50/200 = 25%.
	self1 := "1234 (dsd test) S 1 1234 1234 0 -1 4194560 100 200 0 0 10 0 0 0 0 0 0 20 1"
	self2 := "1234 (dsd test) S 1 1234 1234 0 -1 4194560 100 200 0 0 60 0 0 0 0 0 0 20 1"

	statCalls, selfCalls := 0, 0
	c := &CPUCollector{
		ContainerCtx: platform.ContainerContext{},
		readers: cpuReaders{
			loadAvgOpen: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(loadAvgContent)), nil
			},
			statOpen: func() (io.ReadCloser, error) {
				statCalls++
				if statCalls == 1 {
					return io.NopCloser(strings.NewReader(stat1)), nil
				}
				return io.NopCloser(strings.NewReader(stat2)), nil
			},
			selfStatOpen: func() (io.ReadCloser, error) {
				selfCalls++
				if selfCalls == 1 {
					return io.NopCloser(strings.NewReader(self1)), nil
				}
				return io.NopCloser(strings.NewReader(self2)), nil
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
	// Without self-subtraction this would be 50%; excluding dsd's own 50 jiffies
	// of the 200-jiffy window drops it to ~25%.
	if info.UsagePct < 24 || info.UsagePct > 26 {
		t.Errorf("UsagePct: got %v, want ~25%% (self-subtracted)", info.UsagePct)
	}
}
