//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for pure parsers in disk_linux.go and docker.go — the
// ZFS/SMART output parsers and the Docker exit-code/secret/arch helpers. These
// chew on real command output and are exactly the format-fragile surface worth
// pinning.

func TestParseZFSCount(t *testing.T) {
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"5", 5, true},
		{"0", 0, true},
		{"1.2K", 1200, true},
		{"15M", 15_000_000, true},
		{"3G", 3_000_000_000, true},
		{"2T", 2_000_000_000_000, true},
		{"garbage", 0, false},
		{"K", 0, false}, // too short
	}
	for _, tt := range tests {
		got, ok := parseZFSCount(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseZFSCount(%q) = (%d, %v), want (%d, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseSMARTAttributes(t *testing.T) {
	out := `SMART/Health Information (NVMe Log)
Percentage Used:                    5%
Available Spare:                    100%
Temperature:                        40 Celsius
Media and Data Integrity Errors:    3
Power On Hours:                     7,183`
	var s models.SMARTInfo
	parseSMARTAttributes(out, &s)
	if s.PercentUsed != 5 {
		t.Errorf("PercentUsed = %d, want 5", s.PercentUsed)
	}
	if s.AvailableSpare != 100 {
		t.Errorf("AvailableSpare = %d, want 100", s.AvailableSpare)
	}
	if s.Temperature != 40 {
		t.Errorf("Temperature = %d, want 40", s.Temperature)
	}
	if s.MediaErrors != 3 {
		t.Errorf("MediaErrors = %d, want 3", s.MediaErrors)
	}
	if s.PowerOnHours != 7183 { // thousands separator stripped
		t.Errorf("PowerOnHours = %d, want 7183", s.PowerOnHours)
	}
}

// SATA `smartctl -A` is a colon-less tabular format. The pre-failure sector
// attributes (reallocated / current-pending / offline-uncorrectable) must sum
// into MediaErrors — they used to be skipped by the NVMe colon guard, so a
// degrading SATA drive showed no media-error warning until outright SMART fail.
func TestParseSMARTAttributes_SATA(t *testing.T) {
	out := `SMART Attributes Data Structure revision number: 16
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       8
197 Current_Pending_Sector  0x0032   100   100   000    Old_age   Always       -       3
198 Offline_Uncorrectable   0x0030   100   100   000    Old_age   Offline      -       1
  9 Power_On_Hours          0x0032   095   095   000    Old_age   Always       -       12345
194 Temperature_Celsius     0x0022   035   045   000    Old_age   Always       -       35`
	var s models.SMARTInfo
	parseSMARTAttributes(out, &s)

	// 8 reallocated + 3 pending + 1 uncorrectable = 12.
	if s.MediaErrors != 12 {
		t.Errorf("MediaErrors = %d, want 12 (8+3+1 SATA pre-failure sectors)", s.MediaErrors)
	}
}

func TestIsSATAFailureAttr(t *testing.T) {
	for _, l := range []string{
		"  5 reallocated_sector_ct 0x0033",
		"197 current_pending_sector 0x0032",
		"198 offline_uncorrectable 0x0030",
	} {
		if !isSATAFailureAttr(l) {
			t.Errorf("isSATAFailureAttr(%q) = false, want true", l)
		}
	}
	for _, l := range []string{"  9 power_on_hours", "194 temperature_celsius", "percentage used: 5%"} {
		if isSATAFailureAttr(l) {
			t.Errorf("isSATAFailureAttr(%q) = true, want false", l)
		}
	}
}

func TestTrimSMARTError(t *testing.T) {
	if got := trimSMARTError("smartctl: error opening device /dev/sda"); got != "error opening device /dev/sda" {
		t.Errorf("trimSMARTError = %q", got)
	}
	if got := trimSMARTError("no colon here"); got != "no colon here" {
		t.Errorf("trimSMARTError without colon = %q", got)
	}
}

func TestDiskDetectType_NVMe(t *testing.T) {
	if got := diskDetectType("nvme0n1"); got != models.DriveTypeNVMe {
		t.Errorf("diskDetectType(nvme0n1) = %v, want NVMe", got)
	}
}

func TestDockerExitLabel(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{0, "clean exit"},
		{137, "OOM kill (SIGKILL)"},
		{139, "segfault (SIGSEGV)"},
		{127, "command not found in image"},
		{999, ""}, // unknown
	}
	for _, tt := range tests {
		if got := dockerExitLabel(tt.code); got != tt.want {
			t.Errorf("dockerExitLabel(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestDetectPlaintextSecrets(t *testing.T) {
	env := []string{
		"DB_PASSWORD=hunter2",
		"API_KEY=abc123",
		"PATH=/usr/bin", // starts with / -> skipped
		"DEBUG=true",    // trivial value -> skipped
		"HOME=/root",    // not a secret name
		"GITHUB_TOKEN=ghp_xxx",
	}
	got := detectPlaintextSecrets(env)
	want := map[string]bool{"DB_PASSWORD": true, "API_KEY": true, "GITHUB_TOKEN": true}
	if len(got) != len(want) {
		t.Fatalf("detectPlaintextSecrets = %v, want keys %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected secret name %q in %v", name, got)
		}
	}
}

func TestNormalizeArch(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"x86_64", "amd64"},
		{"aarch64", "arm64"},
		{"armv7l", "arm"},
		{"AMD64", "amd64"}, // unknown -> lower-cased
		{"riscv64", "riscv64"},
	}
	for _, tt := range tests {
		if got := normalizeArch(tt.in); got != tt.want {
			t.Errorf("normalizeArch(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExtractJournalMessage(t *testing.T) {
	if got := extractJournalMessage("May 19 14:05:46 host docker[1]: container started"); got != "container started" {
		t.Errorf("extractJournalMessage = %q, want %q", got, "container started")
	}
	if got := extractJournalMessage("no delimiter here"); got != "" {
		t.Errorf("extractJournalMessage without ': ' = %q, want empty", got)
	}
}
