package collectors

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestNewCPUCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewCPUCollector(platform.ContainerContext{})
	if c.Name() != "CPU Load" {
		t.Errorf("Name() = %q, want %q", c.Name(), "CPU Load")
	}
	wantTimeout := 2 * time.Second
	if runtime.GOOS == "darwin" {
		wantTimeout = 4 * time.Second
	}
	if got := c.Timeout(); got != wantTimeout {
		t.Errorf("Timeout() = %v, want %v", got, wantTimeout)
	}
	// readers must be wired (not nil funcs), or Collect will panic on a real run.
	if c.readers.loadAvgOpen == nil || c.readers.statOpen == nil || c.readers.selfStatOpen == nil {
		t.Error("NewCPUCollector must wire all three readers")
	}
}

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
		{"load5 non-numeric", "0.52 b 0.32 3/412 8932", 0, 0, 0, true},
		{"load15 non-numeric", "0.52 0.43 c 3/412 8932", 0, 0, 0, true},
	}

	for _, tc := range cases {
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

// TestParseCPUStatFullErrors guards parseCPUStatFull's three error branches:
// too-short cpu line, a non-numeric field, and a stat blob with no "cpu "
// aggregate line at all.
func TestParseCPUStatFullErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
	}{
		{"cpu line too short", "cpu  1 2 3\n"},
		{"non-numeric field", "cpu  100 20 notanumber 800 10 0 5 0 0 0\n"},
		{"no cpu line", "cpu0 1 2 3 4 5\nctxt 100\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseCPUStatFull(strings.NewReader(tc.input)); err == nil {
				t.Errorf("parseCPUStatFull(%q) expected an error, got nil", tc.input)
			}
		})
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

// TestCPUCollector_Collect_ContainerLoadPctUsesHostCores is a regression guard:
// /proc/loadavg is never namespaced by cgroups, so it always reflects host-wide
// load. Dividing that by the container's cgroup CPU limit (instead of the real
// host core count) wildly amplifies LoadPct — e.g. a perfectly normal
// fully-utilized 8-core host (load ~8.0) divided by a 1-core container limit
// reads as 800%, corroborating a false CPU-pressure verdict for an otherwise
// idle container.
func TestCPUCollector_Collect_ContainerLoadPctUsesHostCores(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping 500ms CPU sampling in short mode")
	}

	hostCores := runtime.NumCPU()
	// Load average exactly equal to the real host core count = "host fully
	// utilized" = 100% by the correct (host-core) denominator.
	loadAvgContent := fmt.Sprintf("%.2f 0.90 0.50 3/412 8932", float64(hostCores))
	stat1 := "cpu  100 20 30 400 10 0 5 0 0 0\n"
	stat2 := "cpu  110 20 30 440 10 0 5 0 0 0\n"

	callCount := 0
	c := &CPUCollector{
		ContainerCtx: platform.ContainerContext{CPULimitCores: 1}, // a 1-core-limited container
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

	if info.NumCPU != 1 {
		t.Errorf("NumCPU should reflect the container's cgroup limit, got %d", info.NumCPU)
	}
	if info.LoadPct < 90 || info.LoadPct > 110 {
		t.Errorf("LoadPct = %.1f, want ~100%% (host load over the REAL host core count, not the container's 1-core limit)", info.LoadPct)
	}
}

// Regression: CPU usage% must survive capture→replay. The two /proc/stat reads
// share one source key, so the bundle stores a single snapshot; on `dsd replay`
// both reads return it, a recompute collapses the delta to 0%, and checkCPU then
// fires a spurious "0% CPU — load avg N" CRIT the live run never showed. The fix
// caches the DERIVED sample under "cpu/usage-sample" so replay returns the captured
// value. Found on a real k3s-on-VMware capture (live 48%/WARN → replay 0%/CRIT).
func TestCPUCollector_UsageReplaysFaithfully(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 500ms CPU sampling in short mode")
	}
	const loadAvg = "1.50 1.20 0.90 3/412 8932"
	// idle delta=100, total delta=200 → usage = (1 - 100/200)*100 = 50%
	const stat1 = "cpu  100 20 30 400 10 0 5 0 0 0\n"
	const stat2 = "cpu  200 20 30 500 10 0 5 0 0 0\n"

	newCollector := func(reads []string) *CPUCollector {
		i := 0
		return &CPUCollector{
			ContainerCtx: platform.ContainerContext{},
			readers: cpuReaders{
				loadAvgOpen: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(loadAvg)), nil
				},
				statOpen: func() (io.ReadCloser, error) {
					s := reads[i]
					if i < len(reads)-1 {
						i++
					}
					return io.NopCloser(strings.NewReader(s)), nil
				},
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Record pass: two distinct snapshots → real ~50% usage, cached under the key.
	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	recResult, err := newCollector([]string{stat1, stat2}).Collect(ctx)
	SetSource(prev)
	if err != nil {
		t.Fatalf("record Collect: %v", err)
	}
	if u := recResult.(*models.CPUInfo).UsagePct; u < 49 || u > 51 { //nolint:errcheck // asserted type
		t.Fatalf("record UsagePct: got %v, want ~50%%", u)
	}

	// Replay pass: the mock now returns the SAME snapshot twice — a naive recompute
	// would collapse to 0%. The cached derived value must win.
	rp := source.NewReplay(rec.Bundle())
	restore := SetSource(rp)
	defer SetSource(restore)
	rpResult, err := newCollector([]string{stat1, stat1}).Collect(ctx)
	if err != nil {
		t.Fatalf("replay Collect: %v", err)
	}
	if u := rpResult.(*models.CPUInfo).UsagePct; u < 49 || u > 51 { //nolint:errcheck // asserted type
		t.Errorf("replay UsagePct: got %v, want ~50%% (cached value, not recomputed 0%%)", u)
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

// TestParseSelfCPUJiffies_Errors covers the error branches: a reader that
// fails outright, a malformed comm field (no closing paren or nothing after
// it), and too few fields after the comm to reach cstime.
func TestParseSelfCPUJiffies_Errors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input io.Reader
	}{
		{"reader error", iotest.ErrReader(fmt.Errorf("boom"))},
		{"no closing paren", strings.NewReader("1234 (dsd S 1 1234")},
		{"paren at very end", strings.NewReader("1234 (dsd)")},
		{"too few fields after name", strings.NewReader("1234 (dsd) S 1 1234 1234 0 -1 4194560 100 200 0 0 11 7")},
		{"non-numeric field", strings.NewReader("1234 (dsd) S 1 1234 1234 0 -1 4194560 100 200 0 0 x 7 3 1 0 0 0 20 1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseSelfCPUJiffies(tc.input); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestReadSelfJiffies_Fallbacks proves readSelfJiffies is a best-effort
// wrapper: a nil open func, an open() error, and a parse error must all
// return 0 rather than propagating a failure (a failed self-subtraction must
// be a no-op, never corrupt the usage figure).
func TestReadSelfJiffies_Fallbacks(t *testing.T) {
	t.Parallel()
	if got := readSelfJiffies(nil); got != 0 {
		t.Errorf("nil open func: got %d, want 0", got)
	}
	if got := readSelfJiffies(func() (io.ReadCloser, error) {
		return nil, fmt.Errorf("open failed")
	}); got != 0 {
		t.Errorf("open error: got %d, want 0", got)
	}
	if got := readSelfJiffies(func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("garbage")), nil
	}); got != 0 {
		t.Errorf("parse error: got %d, want 0", got)
	}
	if got := readSelfJiffies(func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(
			"42 (dsd) R 1 42 42 0 -1 4194304 50 0 0 0 30 20 0 0 0 0 0 18 1")), nil
	}); got != 50 {
		t.Errorf("happy path: got %d, want 50", got)
	}
}

// TestCPUCollector_SampleCPUUsage_ErrorPaths drives sampleCPUUsage's
// early-return branches directly (statOpen failing on the first call, a
// parse failure on the first sample, ctx cancelled during the sleep window,
// and statOpen failing on the second call) — all must yield a zero cpuSample
// rather than panicking or blocking.
func TestCPUCollector_SampleCPUUsage_ErrorPaths(t *testing.T) {
	t.Parallel()

	t.Run("first statOpen fails", func(t *testing.T) {
		t.Parallel()
		c := &CPUCollector{readers: cpuReaders{
			statOpen: func() (io.ReadCloser, error) { return nil, fmt.Errorf("boom") },
		}}
		s := c.sampleCPUUsage(context.Background())
		if s != (cpuSample{}) {
			t.Errorf("got %+v, want zero value", s)
		}
	})

	t.Run("first sample parse error", func(t *testing.T) {
		t.Parallel()
		c := &CPUCollector{readers: cpuReaders{
			statOpen: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("garbage")), nil
			},
		}}
		s := c.sampleCPUUsage(context.Background())
		if s != (cpuSample{}) {
			t.Errorf("got %+v, want zero value", s)
		}
	})

	t.Run("ctx cancelled during sleep window", func(t *testing.T) {
		t.Parallel()
		c := &CPUCollector{readers: cpuReaders{
			statOpen: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("cpu  100 20 30 400 10 0 5 0 0 0\n")), nil
			},
		}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s := c.sampleCPUUsage(ctx)
		if s != (cpuSample{}) {
			t.Errorf("got %+v, want zero value", s)
		}
	})

	t.Run("second statOpen fails", func(t *testing.T) {
		t.Parallel()
		if testing.Short() {
			t.Skip("skipping 500ms CPU sampling in short mode")
		}
		callCount := 0
		c := &CPUCollector{readers: cpuReaders{
			statOpen: func() (io.ReadCloser, error) {
				callCount++
				if callCount == 1 {
					return io.NopCloser(strings.NewReader("cpu  100 20 30 400 10 0 5 0 0 0\n")), nil
				}
				return nil, fmt.Errorf("second read failed")
			},
		}}
		s := c.sampleCPUUsage(context.Background())
		if s != (cpuSample{}) {
			t.Errorf("got %+v, want zero value", s)
		}
	})
}

// TestCPUCollector_SampleCPUUsage_SelfDeltaExceedsBusy is a regression guard
// for the clamp-to-zero branch: when dsd's own jiffy delta is GREATER than
// the raw busy delta, self-subtraction must clamp busyDelta to 0 (never go
// negative), so UsagePct reads as an honest 0% rather than a nonsensical
// negative usage.
func TestCPUCollector_SampleCPUUsage_SelfDeltaExceedsBusy(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping 500ms CPU sampling in short mode")
	}
	// idle delta=10, total delta=20 → raw busy delta=10.
	stat1 := "cpu  100 0 0 400 0 0 0 0 0 0\n"
	stat2 := "cpu  110 0 0 410 0 0 0 0 0 0\n"
	// dsd's own jiffies delta = 60-0 = 60, which exceeds the raw busy delta (10).
	self1 := "1234 (dsd test) S 1 1234 1234 0 -1 4194560 100 200 0 0 0 0 0 0 0 0 0 20 1"
	self2 := "1234 (dsd test) S 1 1234 1234 0 -1 4194560 100 200 0 0 60 0 0 0 0 0 0 20 1"

	statCalls, selfCalls := 0, 0
	c := &CPUCollector{readers: cpuReaders{
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
	}}
	s := c.sampleCPUUsage(context.Background())
	if s.UsagePct != 0 {
		t.Errorf("UsagePct = %v, want 0 (clamped, self-delta exceeded busy delta)", s.UsagePct)
	}
}

// TestCPUCollector_Collect_LoadAvgOpenFails is a regression guard: on Linux
// (non-darwin), a loadAvgOpen failure must surface as a wrapped "load
// average" error rather than silently falling through to the darwin
// fallback path (which is skipped on this GOOS).
func TestCPUCollector_Collect_LoadAvgOpenFails(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "darwin" {
		t.Skip("this guards the non-darwin error-return path")
	}
	c := &CPUCollector{readers: cpuReaders{
		loadAvgOpen: func() (io.ReadCloser, error) { return nil, fmt.Errorf("boom") },
	}}
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error when loadAvgOpen fails on non-darwin")
	}
	if !strings.Contains(err.Error(), "load average") {
		t.Errorf("error = %q, want it to mention 'load average'", err.Error())
	}
}

func TestParseDarwinCPUUsage(t *testing.T) {
	t.Parallel()
	// Real `top -l 2` output: two samples, the second is authoritative.
	out := "CPU usage: 1.00% user, 1.00% sys, 98.00% idle\n" +
		"some other line\n" +
		"CPU usage: 8.97% user, 4.77% sys, 86.25% idle\n"
	got := parseDarwinCPUUsage(out)
	// Must sum user (8.97) + sys (4.77) from the LAST sample — the prior code
	// keyed off fields[0] ("CPU"), dropped user, and returned only 4.77.
	if want := 8.97 + 4.77; got != want {
		t.Errorf("parseDarwinCPUUsage = %.2f, want %.2f (user+sys of the second sample)", got, want)
	}
	if parseDarwinCPUUsage("no cpu usage line here") != 0 {
		t.Error("missing CPU usage line should yield 0")
	}
	// A malformed percentage field must be skipped (ParseFloat error branch),
	// not crash or contaminate the sum — the well-formed "sys" field still counts.
	if got := parseDarwinCPUUsage("CPU usage: xx% user, 4.77% sys, 86.25% idle\n"); got != 4.77 {
		t.Errorf("parseDarwinCPUUsage with malformed user%% = %.2f, want 4.77 (sys only)", got)
	}
}
