//go:build linux

package collectors

import (
	"reflect"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestParseFuserPIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		out  string
		want []int
	}{
		{
			name: "empty output — no processes found",
			out:  "",
			want: nil,
		},
		{
			// Real `fuser -m` output captured on a Debian 13 (psmisc) host,
			// 2026-07-07: no access-mode suffix at all in this (non -v) mode.
			name: "bare pid list, no access suffix",
			out:  "/mnt/busytest:       738518\n",
			want: []int{738518},
		},
		{
			name: "pids with access-mode suffix letters are still parsed",
			out:  "/var:                1234c  5678F  9012m\n",
			want: []int{1234, 5678, 9012},
		},
		{
			name: "duplicate pid across lines collapses to one entry",
			out:  "/data:               100c\n                     100F\n",
			want: []int{100},
		},
		{
			name: "no colon prefix still parses tokens",
			out:  "1234 5678F\n",
			want: []int{1234, 5678},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseFuserPIDs(tt.out)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseFuserPIDs(%q) = %+v, want %+v", tt.out, got, tt.want)
			}
		})
	}
}

func TestNeedsBusyCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fs   models.FilesystemInfo
		want bool
	}{
		{"below gate, writable, rw", models.FilesystemInfo{FSType: "ext4", UsedPct: 50}, false},
		{"at gate exactly", models.FilesystemInfo{FSType: "ext4", UsedPct: 80}, true},
		{"above gate", models.FilesystemInfo{FSType: "xfs", UsedPct: 95}, true},
		{"read-only below gate", models.FilesystemInfo{FSType: "ext4", UsedPct: 10, ReadOnly: true}, true},
		{"inherently read-only image at 100%", models.FilesystemInfo{FSType: "squashfs", UsedPct: 100, ReadOnly: true}, false},
		{"inherently read-only iso9660", models.FilesystemInfo{FSType: "iso9660", UsedPct: 100, ReadOnly: true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := needsBusyCheck(tt.fs); got != tt.want {
				t.Errorf("needsBusyCheck(%+v) = %v, want %v", tt.fs, got, tt.want)
			}
		})
	}
}

func TestParseFdFlagsWrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		want bool
	}{
		{"read-only fd (O_RDONLY=0)", "pos:\t0\nflags:\t0100000\nmnt_id:\t25\n", false},
		{"write-only fd (O_WRONLY=1)", "pos:\t0\nflags:\t0100001\nmnt_id:\t25\n", true},
		{"read-write fd (O_RDWR=2)", "pos:\t0\nflags:\t0100002\nmnt_id:\t25\n", true},
		{"no flags line", "pos:\t0\nmnt_id:\t25\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseFdFlagsWrite(tt.data); got != tt.want {
				t.Errorf("parseFdFlagsWrite(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}
