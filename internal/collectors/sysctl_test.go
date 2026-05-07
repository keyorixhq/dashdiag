package collectors

import (
	"os"
	"testing"
)

func TestReadIntFile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
		want    int
		wantErr bool
	}{
		{"integer value", "128\n", 128, false},
		{"integer no newline", "4096", 4096, false},
		{"zero", "0\n", 0, false},
		{"large value", "1048576\n", 1048576, false},
		{"empty file", "", 0, true},
		{"non-numeric", "abc\n", 0, true},
		{"float value", "1.5\n", 0, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := os.CreateTemp(t.TempDir(), "sysctl-*")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tc.content); err != nil {
				t.Fatal(err)
			}
			f.Close()

			got, err := readIntFile(f.Name())
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}
