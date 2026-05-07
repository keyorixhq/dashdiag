package collectors

import (
	"context"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

func TestParseVMStat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		input       string
		wantPswpin  uint64
		wantPswpout uint64
		wantErr     bool
	}{
		{
			name:        "healthy (no swap activity)",
			input:       "nr_free_pages 1234567\npswpin 0\npswpout 0\n",
			wantPswpin:  0,
			wantPswpout: 0,
		},
		{
			name:        "active swap",
			input:       "nr_free_pages 100000\npswpin 142\npswpout 89\n",
			wantPswpin:  142,
			wantPswpout: 89,
		},
		{
			name:        "pswpin only",
			input:       "pswpin 5\n",
			wantPswpin:  5,
			wantPswpout: 0,
		},
		{
			name:        "empty input",
			input:       "",
			wantPswpin:  0,
			wantPswpout: 0,
		},
		{
			name:    "malformed pswpin value",
			input:   "pswpin notanumber\n",
			wantErr: true,
		},
		{
			name:    "malformed pswpout value",
			input:   "pswpin 5\npswpout notanumber\n",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pin, pout, err := parseVMStat(strings.NewReader(tc.input))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if pin != tc.wantPswpin {
				t.Errorf("pswpin: got %v, want %v", pin, tc.wantPswpin)
			}
			if pout != tc.wantPswpout {
				t.Errorf("pswpout: got %v, want %v", pout, tc.wantPswpout)
			}
		})
	}
}

func FuzzParseVMStat(f *testing.F) {
	f.Add("nr_free_pages 1234567\npswpin 0\npswpout 0\n")
	f.Add("pswpin 142\npswpout 89\n")
	f.Add("")
	f.Add("pswpin notanumber\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseVMStat(strings.NewReader(s)) //nolint:errcheck
	})
}

func TestParseSwaps(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		input       string
		wantTotalKB uint64
		wantUsedKB  uint64
	}{
		{
			name: "single swap device",
			input: "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n" +
				"/dev/sda5\t\t\t\tpartition\t2097148\t102400\t\t-2\n",
			wantTotalKB: 2097148,
			wantUsedKB:  102400,
		},
		{
			name: "multiple swap devices",
			input: "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n" +
				"/dev/sda5\t\t\t\tpartition\t1048576\t51200\t\t-2\n" +
				"/dev/sdb1\t\t\t\tpartition\t1048576\t51200\t\t-3\n",
			wantTotalKB: 2097152,
			wantUsedKB:  102400,
		},
		{
			name:        "header only (no swap)",
			input:       "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n",
			wantTotalKB: 0,
			wantUsedKB:  0,
		},
		{
			name:        "empty input",
			input:       "",
			wantTotalKB: 0,
			wantUsedKB:  0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			total, used, err := parseSwaps(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if total != tc.wantTotalKB {
				t.Errorf("totalKB: got %v, want %v", total, tc.wantTotalKB)
			}
			if used != tc.wantUsedKB {
				t.Errorf("usedKB: got %v, want %v", used, tc.wantUsedKB)
			}
		})
	}
}

func TestSwapCollector_Collect_InjectableReaders(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "darwin" {
		t.Skip("vmstat sampling not available on darwin")
	}

	callCount := 0
	c := &SwapCollector{
		ContainerCtx: platform.ContainerContext{},
		swapsPath:    "/dev/null", // no swap devices
		readers: swapReaders{
			vmstatOpen: func() (io.ReadCloser, error) {
				callCount++
				if callCount == 1 {
					return io.NopCloser(strings.NewReader("pswpin 100\npswpout 50\n")), nil
				}
				return io.NopCloser(strings.NewReader("pswpin 110\npswpout 60\n")), nil
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := result.(*models.SwapInfo)
	if !ok {
		t.Fatalf("unexpected type %T", result)
	}
	// delta: pin 110-100=10, pout 60-50=10 per second
	if info.PagesInPerSec != 10 {
		t.Errorf("PagesInPerSec: got %v, want 10", info.PagesInPerSec)
	}
	if info.PagesOutPerSec != 10 {
		t.Errorf("PagesOutPerSec: got %v, want 10", info.PagesOutPerSec)
	}
}
