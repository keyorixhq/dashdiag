package collectors

import (
	"os"
	"strings"
	"testing"
)

func TestParseDiskstats(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		input      string
		wantNames  []string
		wantAbsent []string
	}{
		{
			name:      "healthy sda device",
			input:     "   8       0 sda 71816 2896 3467354 44032 37952 7292 819728 83776 0 76256 127808\n",
			wantNames: []string{"sda"},
		},
		{
			name:      "nvme device matches",
			input:     "   259     0 nvme0n1 1000 200 50000 300 800 100 40000 200 0 500 700\n",
			wantNames: []string{"nvme0n1"},
		},
		{
			name:       "loop device excluded",
			input:      "   7       0 loop0 100 0 200 50 0 0 0 0 0 50 50\n",
			wantAbsent: []string{"loop0"},
		},
		{
			name:       "dm device excluded",
			input:      " 253       0 dm-0 500 0 1000 100 200 0 800 50 0 100 150\n",
			wantAbsent: []string{"dm-0"},
		},
		{
			name: "multiple devices mixed",
			input: "   8       0 sda 71816 2896 3467354 44032 37952 7292 819728 83776 0 76256 127808\n" +
				"   7       0 loop0 100 0 200 50 0 0 0 0 0 50 50\n" +
				" 252       0 vda 500 100 2000 200 300 50 1000 100 0 200 300\n",
			wantNames:  []string{"sda", "vda"},
			wantAbsent: []string{"loop0"},
		},
		{
			name:      "line too short is skipped",
			input:     "   8       0 sda 71816\n",
			wantNames: []string{},
		},
		{
			name:      "empty input",
			input:     "",
			wantNames: []string{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := parseDiskstats(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, name := range tc.wantNames {
				if _, ok := result[name]; !ok {
					t.Errorf("expected device %q in result", name)
				}
			}
			for _, name := range tc.wantAbsent {
				if _, ok := result[name]; ok {
					t.Errorf("device %q should be excluded", name)
				}
			}
		})
	}
}

func TestParseDiskstats_FieldValues(t *testing.T) {
	t.Parallel()
	// Verify specific field parsing from the fixture line:
	// sda 71816 2896 3467354 44032 37952 7292 819728 83776 0 76256 127808
	input := "   8       0 sda 71816 2896 3467354 44032 37952 7292 819728 83776 0 76256 127808\n"
	result, err := parseDiskstats(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stat, ok := result["sda"]
	if !ok {
		t.Fatal("sda not found in result")
	}
	if stat.reads != 71816 {
		t.Errorf("reads: got %d, want 71816", stat.reads)
	}
	if stat.readSectors != 3467354 {
		t.Errorf("readSectors: got %d, want 3467354", stat.readSectors)
	}
	if stat.readTimeMs != 44032 {
		t.Errorf("readTimeMs: got %d, want 44032", stat.readTimeMs)
	}
	if stat.writes != 37952 {
		t.Errorf("writes: got %d, want 37952", stat.writes)
	}
	if stat.writeSectors != 819728 {
		t.Errorf("writeSectors: got %d, want 819728", stat.writeSectors)
	}
	if stat.writeTimeMs != 83776 {
		t.Errorf("writeTimeMs: got %d, want 83776", stat.writeTimeMs)
	}
	if stat.ioTimeMs != 76256 {
		t.Errorf("ioTimeMs: got %d, want 76256", stat.ioTimeMs)
	}
}

func TestParseDiskstats_FixtureFile(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/io/diskstats_healthy.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	result, err := parseDiskstats(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result["sda"]; !ok {
		t.Error("sda not found in fixture result")
	}
}

func FuzzParseDiskstats(f *testing.F) {
	f.Add("   8       0 sda 71816 2896 3467354 44032 37952 7292 819728 83776 0 76256 127808\n")
	f.Add("   7       0 loop0 100 0 200 50 0 0 0 0 0 50 50\n")
	f.Add("")
	f.Add("garbage line\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseDiskstats(strings.NewReader(s)) //nolint:errcheck
	})
}
