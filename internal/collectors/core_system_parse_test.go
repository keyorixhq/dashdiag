package collectors

// Tests for uncovered parse-error and edge-case branches in the core-system
// collector group: cpu.go, swap.go, io.go, disk.go, fdlimits.go, memory.go,
// processes.go, sysctl.go, systemd.go.
//
// Each test targets a specific uncovered line or branch identified by the
// coverage report. Darwin-only functions are explicitly skipped.

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// ---------------------------------------------------------------------------
// cpu.go
// ---------------------------------------------------------------------------

// TestCPUCollector_Timeout_NonDarwin guards the Linux/non-darwin Timeout path
// (cpu.go:41-44). On darwin the function returns 4s; on other platforms 2s.
func TestCPUCollector_Timeout_NonDarwin(t *testing.T) {
	t.Parallel()
	c := NewCPUCollector(platform.ContainerContext{})
	got := c.Timeout()
	if runtime.GOOS == "darwin" {
		if got != 4*time.Second {
			t.Errorf("darwin Timeout() = %v, want 4s", got)
		}
	} else {
		if got != 2*time.Second {
			t.Errorf("non-darwin Timeout() = %v, want 2s", got)
		}
	}
}

// TestParseCPUStatFull_WrongFieldCount covers cpu.go:100-101 — the "too few
// fields" error branch that fires when the "cpu " aggregate line has fewer
// than 5 space-separated tokens.
func TestParseCPUStatFull_WrongFieldCount(t *testing.T) {
	t.Parallel()
	// "cpu " line with only 4 tokens (label + 3 values < 5 required).
	input := "cpu  1 2 3\n"
	if _, err := parseCPUStatFull(strings.NewReader(input)); err == nil {
		t.Error("parseCPUStatFull with too-short cpu line: expected error, got nil")
	}
}

// TestCPUCollector_Collect_SecondStatReadFails exercises cpu.go:310 — the
// error branch when the second /proc/stat open fails. sampleCPUUsage returns a
// zero cpuSample in that case; Collect must still succeed using the zero values.
func TestCPUCollector_Collect_SecondStatReadFails(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "darwin" {
		t.Skip("tests Linux /proc/stat read path")
	}
	if testing.Short() {
		t.Skip("skipping 500ms CPU sampling in short mode")
	}

	callCount := 0
	c := &CPUCollector{
		ContainerCtx: platform.ContainerContext{},
		readers: cpuReaders{
			loadAvgOpen: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("0.10 0.20 0.30 1/100 999")), nil
			},
			statOpen: func() (io.ReadCloser, error) {
				callCount++
				if callCount == 1 {
					return io.NopCloser(strings.NewReader("cpu  100 0 0 400 0 0 0 0 0 0\n")), nil
				}
				return nil, fmt.Errorf("second read failed")
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect must succeed even when second stat read fails, got: %v", err)
	}
	if result == nil {
		t.Fatal("Collect must return non-nil result")
	}
}

// ---------------------------------------------------------------------------
// swap.go
// ---------------------------------------------------------------------------

// TestSwapCollector_Collect_SecondVMStatFails covers swap.go:88 (the
// openFile("vmstat (2nd)") error branch). On Linux, a failing second vmstat
// read must still return an error rather than silently succeeding.
func TestSwapCollector_Collect_SecondVMStatFails(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "darwin" {
		t.Skip("vmstat sampling not available on darwin")
	}
	if testing.Short() {
		t.Skip("skipping 1s vmstat sampling in short mode")
	}

	callCount := 0
	c := &SwapCollector{
		ContainerCtx: platform.ContainerContext{},
		swapsPath:    "/dev/null",
		readers: swapReaders{
			vmstatOpen: func() (io.ReadCloser, error) {
				callCount++
				if callCount == 1 {
					return io.NopCloser(strings.NewReader("pswpin 100\npswpout 50\n")), nil
				}
				return nil, fmt.Errorf("second vmstat open failed")
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The second open fails — collectLinux returns an error for the second sample.
	_, err := c.Collect(ctx)
	if err == nil {
		t.Error("Collect should error when second vmstat open fails")
	}
}

// ---------------------------------------------------------------------------
// io.go
// ---------------------------------------------------------------------------

// TestParseDiskstats_ScannerError covers io.go:103 — scanner.Err() propagated
// when the underlying reader fails mid-scan. parseDiskstats must return the
// scanner's error, not silently ignore it.
func TestParseDiskstats_ScannerError(t *testing.T) {
	t.Parallel()
	// iotest.ErrReader returns an error on every Read, triggering scanner.Err().
	_, err := parseDiskstats(iotest.ErrReader(fmt.Errorf("disk read error")))
	if err == nil {
		t.Error("parseDiskstats: expected error from failing reader, got nil")
	}
}

// TestParseDiskstats_ShortLine covers io.go:125 — lines with fewer than 13
// fields are skipped; parseDiskstats must not fail on them but must not include
// any device from them either.
func TestParseDiskstats_ShortLine(t *testing.T) {
	t.Parallel()
	// Valid header but only 7 fields — should be silently skipped.
	input := "   8       0 sda 71816\n"
	result, err := parseDiskstats(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected no devices for short line, got %v", result)
	}
}

// TestParseDiskstats_NonMatchingDevice covers io.go:135 — lines with a device
// name that doesn't match deviceRE are skipped silently.
func TestParseDiskstats_NonMatchingDevice(t *testing.T) {
	t.Parallel()
	// dm-0 does not match deviceRE (no sd/nvme/vd/xvd prefix).
	input := " 253       0 dm-0 500 0 1000 100 200 0 800 50 0 100 150\n"
	result, err := parseDiskstats(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result["dm-0"]; ok {
		t.Error("dm-0 should be excluded by deviceRE filter")
	}
}

// ---------------------------------------------------------------------------
// disk.go
// ---------------------------------------------------------------------------

// TestReadMounts_ScannerError covers disk.go:120 — readMounts returns the
// scanner error when the underlying reader fails.
func TestReadMounts_ScannerError(t *testing.T) {
	t.Parallel()
	_, err := readMounts(iotest.ErrReader(fmt.Errorf("mount read error")))
	if err == nil {
		t.Error("readMounts: expected error from failing reader, got nil")
	}
}

// ---------------------------------------------------------------------------
// fdlimits.go
// ---------------------------------------------------------------------------

// TestParseSoftLimit_TooFewFieldsOnMaxOpenLine covers fdlimits.go:131 — when
// the "Max open files" line has fewer than 4 fields, parseSoftLimit returns -1.
// "Max open files" is already 3 tokens; we need at least one more (the soft
// limit value) to reach fields[3], so a line with only 3 tokens triggers the guard.
func TestParseSoftLimit_TooFewFieldsOnMaxOpenLine(t *testing.T) {
	t.Parallel()
	// Only 3 fields: "Max", "open", "files" — fields[3] would be out of bounds.
	input := "Max open files\n"
	got := parseSoftLimit(strings.NewReader(input))
	if got != -1 {
		t.Errorf("too-few-fields Max open files line: got %d, want -1", got)
	}
}

// TestParseSoftLimit_NonNumericValue covers fdlimits.go:144 — when fields[3]
// is not "unlimited" and not a number, parseSoftLimit returns -1.
func TestParseSoftLimit_NonNumericValue(t *testing.T) {
	t.Parallel()
	input := "Max open files            notanumber           4096                 files\n"
	got := parseSoftLimit(strings.NewReader(input))
	if got != -1 {
		t.Errorf("non-numeric soft limit: got %d, want -1", got)
	}
}

// TestParseFileNr_NonNumericOpen covers fdlimits.go:212 — parseFileNr returns
// an error when the open-fds field can't be parsed.
func TestParseFileNr_NonNumericOpen(t *testing.T) {
	t.Parallel()
	_, _, err := parseFileNr(strings.NewReader("abc 0 1048576\n"))
	if err == nil {
		t.Error("parseFileNr with non-numeric open count: expected error, got nil")
	}
}

// TestParseFileNr_NonNumericMax covers fdlimits.go:223-232 area — parseFileNr
// returns an error when the max-fds field can't be parsed.
func TestParseFileNr_NonNumericMax(t *testing.T) {
	t.Parallel()
	_, _, err := parseFileNr(strings.NewReader("4821 0 notanumber\n"))
	if err == nil {
		t.Error("parseFileNr with non-numeric max count: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// memory.go
// ---------------------------------------------------------------------------

// TestParseMeminfo_NonNumericValueSkipped covers memory.go:88-90 — lines
// where the value after stripping " kB" isn't a valid uint64 are silently
// skipped; the function must not error.
func TestParseMeminfo_NonNumericValueSkipped(t *testing.T) {
	t.Parallel()
	input := "BadKey: notanumber kB\nMemTotal: 1024 kB\n"
	result, err := parseMeminfo(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result["BadKey"]; ok {
		t.Error("non-numeric key should be skipped, but was included")
	}
	if result["MemTotal"] != 1024 {
		t.Errorf("MemTotal: got %d, want 1024", result["MemTotal"])
	}
}

// TestParseMeminfo_UnitNotKB covers memory.go:90 — when the value suffix is
// not " kB", stripping it leaves behind a non-numeric string that fails
// ParseUint, so the line is silently skipped.
func TestParseMeminfo_UnitNotKB(t *testing.T) {
	t.Parallel()
	// "MB" suffix is not stripped — "1024 MB" fails ParseUint → skip.
	input := "MemTotal: 1024 MB\nMemFree: 512 kB\n"
	result, err := parseMeminfo(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result["MemTotal"]; ok {
		t.Error("MemTotal with 'MB' unit should be skipped")
	}
	if result["MemFree"] != 512 {
		t.Errorf("MemFree: got %d, want 512", result["MemFree"])
	}
}

// TestParseMeminfo_ScannerError covers memory.go:130 area — scanner.Err() is
// propagated when the underlying reader fails.
func TestParseMeminfo_ScannerError(t *testing.T) {
	t.Parallel()
	_, err := parseMeminfo(iotest.ErrReader(fmt.Errorf("meminfo read error")))
	if err == nil {
		t.Error("parseMeminfo: expected error from failing reader, got nil")
	}
}

// ---------------------------------------------------------------------------
// processes.go
// ---------------------------------------------------------------------------

// TestParseProcStat_TooFewFieldsAfterName covers processes.go:68 — when there
// are fewer than 2 fields after the closing paren, parseProcStat returns an error.
func TestParseProcStat_TooFewFieldsAfterName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
	}{
		{"only state no ppid", "1234 (nginx) S"},
		{"empty after paren", "1234 (nginx) "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := parseProcStat([]byte(tc.input))
			if err == nil {
				t.Errorf("parseProcStat(%q): expected error for too-few fields, got nil", tc.input)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sysctl.go
// ---------------------------------------------------------------------------

// TestReadIntFile_NonExistentPath covers sysctl.go:70 area — readIntFile must
// return an error when the path does not exist.
func TestReadIntFile_NonExistentPath(t *testing.T) {
	t.Parallel()
	_, err := readIntFile("/nonexistent/subdir/that/cannot/exist/value")
	if err == nil {
		t.Error("readIntFile: expected error for non-existent path, got nil")
	}
}

// ---------------------------------------------------------------------------
// systemd.go
// ---------------------------------------------------------------------------

// TestParseUnitList_ScannerError covers systemd.go:44 — parseUnitList wraps and
// returns the scanner error when the underlying reader fails.
func TestParseUnitList_ScannerError(t *testing.T) {
	t.Parallel()
	_, err := parseUnitList(iotest.ErrReader(fmt.Errorf("unit list read error")))
	if err == nil {
		t.Error("parseUnitList: expected error from failing reader, got nil")
	}
}

// TestParseUnitList_BulletWithNoDotInField1 covers systemd.go:292 —
// when fields[0] has no dot AND fields[1] also has no dot, the line is skipped.
// The fallback "fields[1] might be the unit name" branch checks fields[1] for a
// dot; if absent, the line is skipped entirely.
func TestParseUnitList_BulletWithNoDotInField1(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		input     string
		wantCount int
	}{
		{
			name:      "bullet with no dot in either field",
			input:     "* foo bar baz\n",
			wantCount: 0,
		},
		{
			name:      "bullet with unit name in field 1",
			input:     "* nginx.service loaded failed failed nginx\n",
			wantCount: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseUnitList(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantCount {
				t.Errorf("got %d units, want %d (units: %v)", len(got), tc.wantCount, got)
			}
		})
	}
}

// TestParseBlameSlowUnits_SingleTokenLine covers systemd.go:437 — a line with
// only one field (no space, so no separate unit name and duration tokens)
// must be skipped without panic.
func TestParseBlameSlowUnits_SingleTokenLine(t *testing.T) {
	t.Parallel()
	// A single-token line: fields < 2 → must be skipped.
	blameOut := "singletoken\n" +
		"12.345s real.service\n"
	got := parseBlameSlowUnits(blameOut, nil)
	// Only the valid line contributes; the single-token line is skipped.
	if len(got) != 1 || got[0].Name != "real.service" {
		t.Errorf("expected [real.service], got %v", got)
	}
}

// TestParseBlameSlowUnits_BelowThresholdSkippedNotStopped covers the dur < 5.0
// branch: a sub-threshold line must be skipped, not treated as a sorted-output
// end-of-list marker. blame's stdout is untrusted external-tool output — an
// unsorted or adversarially-crafted line ordering must not cause a later
// genuinely-slow unit to be silently dropped (internal-collectors-32-05).
func TestParseBlameSlowUnits_BelowThresholdSkippedNotStopped(t *testing.T) {
	t.Parallel()
	blameOut := "10.000s slow.service\n" +
		"4.999s fast.service\n" + // < 5s — must be skipped, not treated as end-of-list
		"8.000s should-still-appear.service\n" // must still surface, sorted after slow.service
	got := parseBlameSlowUnits(blameOut, nil)
	if len(got) != 2 || got[0].Name != "slow.service" || got[1].Name != "should-still-appear.service" {
		t.Errorf("expected [slow.service, should-still-appear.service] sorted by duration, got %v", got)
	}
}

// TestParseBlameSlowUnits_NoDotSkipped covers the "!strings.Contains(name, '.')"
// branch — a unit name with no dot is skipped.
func TestParseBlameSlowUnits_NoDotSkipped(t *testing.T) {
	t.Parallel()
	blameOut := "12.000s nodotunit\n" +
		"11.000s real.service\n"
	got := parseBlameSlowUnits(blameOut, nil)
	for _, u := range got {
		if u.Name == "nodotunit" {
			t.Error("unit with no dot should be skipped")
		}
	}
}
