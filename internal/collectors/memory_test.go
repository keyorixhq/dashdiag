package collectors

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

func TestParseMeminfo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		wantKeys map[string]uint64
	}{
		{
			name: "typical linux meminfo",
			input: `MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
Slab:             512000 kB
CommitLimit:    32768000 kB
Committed_AS:   10240000 kB
`,
			wantKeys: map[string]uint64{
				"MemTotal":     16384000,
				"MemFree":      2048000,
				"MemAvailable": 8192000,
				"Slab":         512000,
				"CommitLimit":  32768000,
				"Committed_AS": 10240000,
			},
		},
		{
			name:     "empty input",
			input:    "",
			wantKeys: map[string]uint64{},
		},
		{
			name:     "lines without colon are skipped",
			input:    "no colon here\nMemTotal: 1024 kB\n",
			wantKeys: map[string]uint64{"MemTotal": 1024},
		},
		{
			name:     "non-numeric values are skipped",
			input:    "BadKey: notanumber kB\nMemFree: 4096 kB\n",
			wantKeys: map[string]uint64{"MemFree": 4096},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := parseMeminfo(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k, want := range tc.wantKeys {
				got, ok := result[k]
				if !ok {
					t.Errorf("key %q missing from result", k)
					continue
				}
				if got != want {
					t.Errorf("key %q: got %v, want %v", k, got, want)
				}
			}
		})
	}
}

func FuzzParseMeminfo(f *testing.F) {
	f.Add("MemTotal: 16384000 kB\nSlab: 512000 kB\n")
	f.Add("")
	f.Add("no colon here\n")
	f.Add("BadKey: notanumber kB\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseMeminfo(strings.NewReader(s)) //nolint:errcheck
	})
}

func TestMemoryCollector_Collect_TempFile(t *testing.T) {
	t.Parallel()

	content := `MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
Slab:             512000 kB
CommitLimit:    32768000 kB
Committed_AS:   10240000 kB
`
	f, err := os.CreateTemp(t.TempDir(), "meminfo-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := &MemoryCollector{
		meminfoPath:  f.Name(),
		ContainerCtx: platform.ContainerContext{},
	}

	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}
