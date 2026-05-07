package collectors

import (
	"os"
	"strings"
	"testing"
)

func TestParseTimedatectl(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		input        string
		wantSynced   bool
		wantOffsetMs float64
		wantErr      bool
	}{
		{
			name:         "healthy synced",
			input:        "NTPSynchronized=yes\nNTPOffsetUsec=4231\n",
			wantSynced:   true,
			wantOffsetMs: 4.231,
		},
		{
			name:         "unsynced",
			input:        "NTPSynchronized=no\nNTPOffsetUsec=0\n",
			wantSynced:   false,
			wantOffsetMs: 0,
		},
		{
			name:         "synced without offset",
			input:        "NTPSynchronized=yes\n",
			wantSynced:   true,
			wantOffsetMs: 0,
		},
		{
			name:    "malformed offset value",
			input:   "NTPSynchronized=yes\nNTPOffsetUsec=notanumber\n",
			wantErr: true,
		},
		{
			name:         "empty input",
			input:        "",
			wantSynced:   false,
			wantOffsetMs: 0,
		},
		{
			name:         "unknown keys ignored",
			input:        "Timezone=UTC\nNTPSynchronized=yes\nNTPOffsetUsec=1000\n",
			wantSynced:   true,
			wantOffsetMs: 1.0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synced, offsetMs, err := parseTimedatectl(strings.NewReader(tc.input))
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
			if !approxEqual(offsetMs, tc.wantOffsetMs, 0.001) {
				t.Errorf("offsetMs: got %v, want %v", offsetMs, tc.wantOffsetMs)
			}
		})
	}
}

func TestParseTimedatectl_HealthyFixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/clock/timedatectl_healthy.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()
	synced, offsetMs, err := parseTimedatectl(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !synced {
		t.Error("want synced=true")
	}
	if !approxEqual(offsetMs, 4.231, 0.001) {
		t.Errorf("offsetMs: got %v, want ~4.231", offsetMs)
	}
}

func TestParseTimedatectl_UnsyncedFixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/clock/timedatectl_unsynced.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()
	synced, _, err := parseTimedatectl(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if synced {
		t.Error("want synced=false")
	}
}

func TestParseChronyTracking(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		wantMs  float64
		wantErr bool
	}{
		{
			name:    "healthy tracking",
			input:   "Reference ID    : A29FC205 (time.cloudflare.com)\nSystem time     : 0.000123456 seconds slow of NTP time\n",
			wantMs:  0.123456,
			wantErr: false,
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
			ms, err := parseChronyTracking(strings.NewReader(tc.input))
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
				t.Errorf("ms: got %v, want ~%v", ms, tc.wantMs)
			}
		})
	}
}

func FuzzParseTimedatectl(f *testing.F) {
	f.Add("NTPSynchronized=yes\nNTPOffsetUsec=4231\n")
	f.Add("NTPSynchronized=no\nNTPOffsetUsec=0\n")
	f.Add("")
	f.Add("garbage=value\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseTimedatectl(strings.NewReader(s)) //nolint:errcheck
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
