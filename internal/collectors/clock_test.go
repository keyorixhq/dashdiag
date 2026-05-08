package collectors

import (
	"os"
	"strings"
	"testing"
)

func TestParseTimesyncStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		offsetStr string
		wantMs    float64
		wantErr   bool
	}{
		{name: "+1.866ms", offsetStr: "+1.866ms", wantMs: 1.866},
		{name: "-0.500ms", offsetStr: "-0.500ms", wantMs: -0.500},
		{name: "+123us", offsetStr: "+123us", wantMs: 0.123},
		{name: "+0.001s", offsetStr: "+0.001s", wantMs: 1.0},
		{name: "garbage", offsetStr: "garbage", wantErr: true},
		{name: "empty", offsetStr: "", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := "       Offset: " + tc.offsetStr + "\n"
			ms, err := parseTimesyncStatus(strings.NewReader(input))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if !approxEqual(ms, tc.wantMs, 0.001) {
				t.Errorf("ms: got %v, want %v", ms, tc.wantMs)
			}
		})
	}
}

func TestParseTimesyncStatus_NoOffsetLine(t *testing.T) {
	t.Parallel()
	_, err := parseTimesyncStatus(strings.NewReader("Server: 1.2.3.4\nDelay: 1ms\n"))
	if err == nil {
		t.Fatal("expected error when Offset: line is absent")
	}
}

func TestParseTimesyncStatus_Fixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/clock/timesync_status_ubuntu24.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()
	ms, err := parseTimesyncStatus(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !approxEqual(ms, 1.866, 0.001) {
		t.Errorf("ms: got %v, want ~1.866", ms)
	}
}

func TestParseChronyTracking(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		input      string
		wantSynced bool
		wantMs     float64
		wantErr    bool
	}{
		{
			name:       "healthy tracking",
			input:      "Reference ID    : A29FC205 (time.cloudflare.com)\nSystem time     : 0.000123456 seconds slow of NTP time\n",
			wantSynced: true,
			wantMs:     0.123456,
		},
		{
			name:    "no system time line",
			input:   "Reference ID    : A29FC205 (time.cloudflare.com)\n",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synced, ms, err := parseChronyTracking(strings.NewReader(tc.input))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if synced != tc.wantSynced {
				t.Errorf("synced: got %v, want %v", synced, tc.wantSynced)
			}
			if !approxEqual(ms, tc.wantMs, 0.001) {
				t.Errorf("ms: got %v, want ~%v", ms, tc.wantMs)
			}
		})
	}
}

func TestParseChronyTracking_Fixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/clock/chrony_tracking.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()
	synced, ms, err := parseChronyTracking(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !synced {
		t.Error("want synced=true")
	}
	if !approxEqual(ms, 0.123456, 0.001) {
		t.Errorf("ms: got %v, want ~0.123456", ms)
	}
}

func FuzzParseTimesyncStatus(f *testing.F) {
	f.Add("       Offset: +1.866ms\n")
	f.Add("       Offset: -0.500ms\n")
	f.Add("       Offset: +123us\n")
	f.Add("       Offset: +0.001s\n")
	f.Add("       Offset: \n")
	f.Add("")
	f.Add("garbage\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseTimesyncStatus(strings.NewReader(s)) //nolint:errcheck
	})
}

// approxEqual compares two floats within an absolute tolerance.
func approxEqual(a, b, tol float64) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff <= tol
}
