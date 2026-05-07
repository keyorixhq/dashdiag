package collectors

import (
	"os"
	"strings"
	"testing"
)

func TestParseFileNr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		wantOpen uint64
		wantMax  uint64
		wantErr  bool
	}{
		{
			name:     "healthy",
			input:    "4821\t0\t1048576\n",
			wantOpen: 4821,
			wantMax:  1048576,
		},
		{
			name:     "space separated",
			input:    "4821  0  1048576\n",
			wantOpen: 4821,
			wantMax:  1048576,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "too few fields",
			input:   "4821 0\n",
			wantErr: true,
		},
		{
			name:    "non-numeric open",
			input:   "abc 0 1048576\n",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			open, max, err := parseFileNr(strings.NewReader(tc.input))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if open != tc.wantOpen {
				t.Errorf("open: got %d, want %d", open, tc.wantOpen)
			}
			if max != tc.wantMax {
				t.Errorf("max: got %d, want %d", max, tc.wantMax)
			}
		})
	}
}

func TestParseFileNr_Fixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/fdlimits/file_nr.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()
	open, max, err := parseFileNr(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if open != 4821 {
		t.Errorf("open: got %d, want 4821", open)
	}
	if max != 1048576 {
		t.Errorf("max: got %d, want 1048576", max)
	}
}

func TestParseSoftLimit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			name: "standard limits file",
			input: "Limit                     Soft Limit           Hard Limit           Units\n" +
				"Max open files            1024                 4096                 files\n",
			want: 1024,
		},
		{
			name: "unlimited soft limit",
			input: "Limit                     Soft Limit           Hard Limit           Units\n" +
				"Max open files            unlimited            unlimited            files\n",
			want: 2147483647,
		},
		{
			name:  "no Max open files line",
			input: "Limit                     Soft Limit           Hard Limit           Units\n",
			want:  -1,
		},
		{
			name:  "empty",
			input: "",
			want:  -1,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseSoftLimit(strings.NewReader(tc.input))
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseSoftLimit_Fixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/fdlimits/limits.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()
	got := parseSoftLimit(f)
	if got != 1024 {
		t.Errorf("got %d, want 1024", got)
	}
}

func FuzzParseFileNr(f *testing.F) {
	f.Add("4821\t0\t1048576\n")
	f.Add("")
	f.Add("abc 0 1048576\n")
	f.Add("4821\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseFileNr(strings.NewReader(s)) //nolint:errcheck
	})
}
