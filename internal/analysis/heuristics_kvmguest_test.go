package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for the KVM/Proxmox guest heuristics — checkKVMGuest and
// its exported KVMGuestInsights wrapper. Pure (models struct in, []Insight out).

func TestKVMGuestInsights_NotGuest(t *testing.T) {
	t.Parallel()
	out := KVMGuestInsights(models.KVMGuestInfo{IsGuest: false})
	if out != nil {
		t.Errorf("non-guest host must produce no KVM guest insights, got %+v", out)
	}
}

func TestKVMGuestInsights_AdaptsHostHints(t *testing.T) {
	t.Parallel()
	// KVMGuestInsights must run checkKVMGuest through AdaptHostHints — exercise the
	// exported entry point directly (cmd↔health consistency contract).
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		QGAInstalled:      true,
		QGARunning:        true,
		Clocksource:       "kvm-clock",
	}
	out := KVMGuestInsights(v)
	if len(out) == 0 {
		t.Fatal("expected at least the all-clean recognition insight")
	}
}

func TestCheckKVMGuest_AllClean(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		ProductName:       "Standard PC (Q35 + ICH9, 2009)",
		QGAChannelPresent: true,
		QGAInstalled:      true,
		QGARunning:        true,
		Clocksource:       "kvm-clock",
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "INFO", "QEMU/KVM guest") {
		t.Errorf("all-clean guest must produce one recognition INFO line, got %+v", out)
	}
	if len(out) != 1 {
		t.Errorf("all-clean guest must produce exactly one insight, got %d: %+v", len(out), out)
	}
}

func TestCheckKVMGuest_AllCleanUnknownProductAndClocksource(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		QGAInstalled:      true,
		QGARunning:        true,
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "INFO", "QEMU/KVM guest (QEMU)") {
		t.Errorf("empty ProductName must fall back to 'QEMU', got %+v", out)
	}
	if !hasInsightMsg(out, "INFO", "clocksource unknown") {
		t.Errorf("empty Clocksource must fall back to 'unknown', got %+v", out)
	}
}

func TestCheckKVMGuest_EmulatedNICs(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		QGAInstalled:      true,
		QGARunning:        true,
		Clocksource:       "kvm-clock",
		EmulatedNICs:      []string{"eth0"},
		NICDrivers:        map[string]string{"eth0": "e1000"},
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "WARN", "eth0 (e1000)") {
		t.Errorf("emulated NIC with known driver must be named with driver, got %+v", out)
	}
	if !hasInsightMsg(out, "WARN", "VirtIO") {
		t.Errorf("emulated NIC insight must suggest VirtIO, got %+v", out)
	}
}

func TestCheckKVMGuest_EmulatedNICsUnknownDriver(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		QGAInstalled:      true,
		QGARunning:        true,
		Clocksource:       "kvm-clock",
		EmulatedNICs:      []string{"eth1"},
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "WARN", "eth1") {
		t.Errorf("emulated NIC without a known driver must still be named by iface, got %+v", out)
	}
}

func TestCheckKVMGuest_EmulatedDisks(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		QGAInstalled:      true,
		QGARunning:        true,
		Clocksource:       "kvm-clock",
		EmulatedDisks:     []string{"sda"},
		DiskBuses:         map[string]string{"sda": "ide"},
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "WARN", "sda (ide)") {
		t.Errorf("emulated disk with known bus must be named with bus, got %+v", out)
	}
	if !hasInsightMsg(out, "WARN", "VirtIO Block or VirtIO SCSI") {
		t.Errorf("emulated disk insight must suggest VirtIO, got %+v", out)
	}
}

func TestCheckKVMGuest_EmulatedDisksUnknownBus(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		QGAInstalled:      true,
		QGARunning:        true,
		Clocksource:       "kvm-clock",
		EmulatedDisks:     []string{"sdb"},
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "WARN", "sdb") {
		t.Errorf("emulated disk without a known bus must still be named by device, got %+v", out)
	}
}

func TestCheckKVMGuest_NonKVMClocksource(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		QGAInstalled:      true,
		QGARunning:        true,
		Clocksource:       "tsc",
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "INFO", `clocksource is "tsc"`) {
		t.Errorf("non-kvm-clock clocksource must be flagged INFO, got %+v", out)
	}
}

func TestCheckKVMGuest_QGAChannelAbsent(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{IsGuest: true, Clocksource: "kvm-clock"}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "INFO", "no QEMU guest-agent channel") {
		t.Errorf("missing QGA channel must be INFO (host-side), got %+v", out)
	}
}

func TestCheckKVMGuest_QGAChannelPresentNotInstalled(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		Clocksource:       "kvm-clock",
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "WARN", "not installed") {
		t.Errorf("QGA channel present but agent not installed must WARN 'not installed', got %+v", out)
	}
}

func TestCheckKVMGuest_QGAChannelPresentInstalledNotRunning(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		IsGuest:           true,
		QGAChannelPresent: true,
		QGAInstalled:      true,
		Clocksource:       "kvm-clock",
	}
	out := checkKVMGuest(v)
	if !hasInsightMsg(out, "WARN", "installed but not running") {
		t.Errorf("QGA installed but not running must WARN with that reason, got %+v", out)
	}
}

func TestCheckKVMGuest_StealPctBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		stealPct float64
		wantWarn bool
	}{
		{"below threshold", kvmGuestStealWarnPct - 0.1, false},
		{"at threshold", kvmGuestStealWarnPct, true},
		{"above threshold", kvmGuestStealWarnPct + 5, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := models.KVMGuestInfo{
				IsGuest:           true,
				QGAChannelPresent: true,
				QGAInstalled:      true,
				QGARunning:        true,
				Clocksource:       "kvm-clock",
				StealPct:          tt.stealPct,
			}
			out := checkKVMGuest(v)
			got := hasInsightMsg(out, "WARN", "CPU steal is")
			if got != tt.wantWarn {
				t.Errorf("stealPct=%.1f: wantWarn=%v got=%v (%+v)", tt.stealPct, tt.wantWarn, got, out)
			}
		})
	}
}

func TestKvmguestNICDescs_Multiple(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		EmulatedNICs: []string{"eth0", "eth1"},
		NICDrivers:   map[string]string{"eth0": "e1000", "eth1": "rtl8139"},
	}
	got := kvmguestNICDescs(v)
	want := "eth0 (e1000), eth1 (rtl8139)"
	if got != want {
		t.Errorf("kvmguestNICDescs() = %q, want %q", got, want)
	}
}

func TestKvmguestDiskDescs_Multiple(t *testing.T) {
	t.Parallel()
	v := models.KVMGuestInfo{
		EmulatedDisks: []string{"sda", "sdb"},
		DiskBuses:     map[string]string{"sda": "ide", "sdb": "sata"},
	}
	got := kvmguestDiskDescs(v)
	want := "sda (ide), sdb (sata)"
	if got != want {
		t.Errorf("kvmguestDiskDescs() = %q, want %q", got, want)
	}
}

func TestKvmguestProductName(t *testing.T) {
	t.Parallel()
	if got := kvmguestProductName(models.KVMGuestInfo{}); got != "QEMU" {
		t.Errorf("empty ProductName must fall back to QEMU, got %q", got)
	}
	if got := kvmguestProductName(models.KVMGuestInfo{ProductName: "Custom"}); got != "Custom" {
		t.Errorf("non-empty ProductName must be returned as-is, got %q", got)
	}
}

func TestKvmguestOrUnknown(t *testing.T) {
	t.Parallel()
	if got := kvmguestOrUnknown(""); got != "unknown" {
		t.Errorf("empty string must fall back to unknown, got %q", got)
	}
	if got := kvmguestOrUnknown("kvm-clock"); got != "kvm-clock" {
		t.Errorf("non-empty string must be returned as-is, got %q", got)
	}
}
