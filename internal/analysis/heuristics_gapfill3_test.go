package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for small pure formatting/classification helpers across
// heuristics_aws.go, heuristics_azure.go, heuristics_network.go, heuristics_security.go,
// and heuristics_virt.go — each is a leaf function with no I/O, tested directly.

func TestMicroDur(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		us   uint64
		want string
	}{
		{"microseconds", 500, "500µs"},
		{"just under 1ms", 999, "999µs"},
		{"milliseconds", 1_500, "1ms"},
		{"just under 1s", 999_999, "999ms"},
		{"seconds", 2_500_000, "2.5s"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := microDur(tt.us); got != tt.want {
				t.Errorf("microDur(%d) = %q, want %q", tt.us, got, tt.want)
			}
		})
	}
}

func TestDiskLabel(t *testing.T) {
	t.Parallel()
	if got := diskLabel(models.AzureDisk{Name: "osdisk"}); got != "osdisk" {
		t.Errorf("named disk = %q, want osdisk", got)
	}
	if got := diskLabel(models.AzureDisk{}); got != "unnamed" {
		t.Errorf("empty disk name = %q, want unnamed", got)
	}
}

func TestAnDrivers(t *testing.T) {
	t.Parallel()
	if got := anDrivers(models.AzureInfo{}); got != "VF" {
		t.Errorf("no AN VFs = %q, want VF", got)
	}
	a := models.AzureInfo{AN: []models.ANIface{
		{Driver: "mlx5_core"}, {Driver: "mlx5_core"}, {Driver: "mana"},
	}}
	if got := anDrivers(a); got != "mana, mlx5_core" {
		t.Errorf("mixed drivers = %q, want sorted+deduped 'mana, mlx5_core'", got)
	}
}

func TestRateSuffix(t *testing.T) {
	t.Parallel()
	if got := rateSuffix(-1); got != "" {
		t.Errorf("negative rate = %q, want empty", got)
	}
	if got := rateSuffix(2.5); got != " (~2.5/hr)" {
		t.Errorf("positive rate = %q, want ' (~2.5/hr)'", got)
	}
	if got := rateSuffix(0); got != " (~0.0/hr)" {
		t.Errorf("zero rate = %q, want ' (~0.0/hr)'", got)
	}
}

func TestCloudFirewallLabels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		provider  string
		wantLabel string
		wantTerm  string
	}{
		{"aws", "AWS EC2", "Security Group"},
		{"azure", "Azure", "Network Security Group (NSG)"},
		{"gcp", "GCP", "VPC firewall rules"},
		{"unknown-provider", "cloud", "cloud network firewall"},
		{"", "cloud", "cloud network firewall"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.provider, func(t *testing.T) {
			t.Parallel()
			label, term, where := cloudFirewallLabels(tt.provider)
			if label != tt.wantLabel {
				t.Errorf("label = %q, want %q", label, tt.wantLabel)
			}
			if term != tt.wantTerm {
				t.Errorf("term = %q, want %q", term, tt.wantTerm)
			}
			if where == "" {
				t.Error("where must not be empty")
			}
		})
	}
}

func TestTruncateSELinux(t *testing.T) {
	t.Parallel()
	if got := truncateSELinux("short", 10); got != "short" {
		t.Errorf("under-limit string must pass through, got %q", got)
	}
	if got := truncateSELinux("exactly10c", 10); got != "exactly10c" {
		t.Errorf("exact-limit string must pass through, got %q", got)
	}
	if got := truncateSELinux("this is definitely too long", 10); got != "this is de…" {
		t.Errorf("over-limit string must truncate with ellipsis, got %q", got)
	}
}

func TestK8sFirstLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"single line", "hello", "hello"},
		{"leading blank lines", "\n\n  \nhello world", "hello world"},
		{"multi line takes first nonblank", "  first  \nsecond\nthird", "first"},
		{"all blank returns original", "\n  \n\t\n", "\n  \n\t\n"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := k8sFirstLine(tt.in); got != tt.want {
				t.Errorf("k8sFirstLine(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
