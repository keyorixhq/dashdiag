//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestIsGCPGuest(t *testing.T) {
	cases := []struct {
		name             string
		product, sysVend string
		want             bool
	}{
		{"gce product name", "Google Compute Engine", "Google", true},
		{"google sys_vendor only", "", "Google", true},
		{"aws not gcp", "t3.micro", "Amazon EC2", false},
		{"vmware not gcp", "VMware7,1", "VMware, Inc.", false},
		{"empty", "", "", false},
	}
	for _, c := range cases {
		if got := isGCPGuest(c.product, c.sysVend); got != c.want {
			t.Errorf("%s: isGCPGuest=%v want %v", c.name, got, c.want)
		}
	}
}

func TestGCPNICDriver(t *testing.T) {
	// gVNIC present → usesGVNIC true, primary (alphabetically-first) driver reported.
	netDir := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir, "eth0", "gve", "up")
	drv, gvnic := gcpNICDriver(netDir)
	if drv != "gve" || !gvnic {
		t.Errorf("gve NIC: driver=%q usesGVNIC=%v, want gve/true", drv, gvnic)
	}

	// virtio_net only → not gVNIC (valid, not a fault).
	netDir2 := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir2, "ens4", "virtio_net", "up")
	drv2, gvnic2 := gcpNICDriver(netDir2)
	if drv2 != "virtio_net" || gvnic2 {
		t.Errorf("virtio NIC: driver=%q usesGVNIC=%v, want virtio_net/false", drv2, gvnic2)
	}

	// No NICs → empty, not a crash.
	if drv3, gvnic3 := gcpNICDriver(filepath.Join(t.TempDir(), "empty")); drv3 != "" || gvnic3 {
		t.Errorf("no NICs: driver=%q usesGVNIC=%v, want empty/false", drv3, gvnic3)
	}
}

// ── constructor / interface methods ──────────────────────────────────────────

func TestNewGCPCollector_NameAndTimeout(t *testing.T) {
	c := NewGCPCollector()
	if c.Name() != "GCP" {
		t.Errorf("Name() = %q, want GCP", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

// ── GCPGuestAvailable ─────────────────────────────────────────────────────────

func TestGCPGuestAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile(dmiIDDir+"/product_name", []byte("Google Compute Engine\n"))
		b.PutFile(dmiIDDir+"/sys_vendor", []byte("Google\n"))
	})
	if !GCPGuestAvailable() {
		t.Error("expected true on a GCE DMI signature")
	}
}

func TestGCPGuestAvailable_NotGCP(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile(dmiIDDir+"/product_name", []byte("VMware7,1\n"))
		b.PutFile(dmiIDDir+"/sys_vendor", []byte("VMware, Inc.\n"))
	})
	if GCPGuestAvailable() {
		t.Error("expected false on a non-GCE DMI signature")
	}
}

// ── Collect (integration) ────────────────────────────────────────────────────

func TestGCPCollector_Collect(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/google_guest_agent": []byte("/usr/bin/google_guest_agent"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/scheduling/on-host-maintenance": []byte("MIGRATE"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/scheduling/preemptible":         []byte("false"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/maintenance-event":              []byte("NONE"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/attributes/enable-oslogin":      []byte("TRUE"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "google-guest-agent"}, "active\n", 0)
		b.PutFile("/etc/chrony.conf", []byte("server metadata.google.internal iburst\n"))
	})

	c := NewGCPCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.GCPInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.GCPInfo", result)
	}
	if !info.IsGCP {
		t.Error("expected IsGCP=true")
	}
	if !info.GuestAgentInstalled || !info.GuestAgentRunning {
		t.Errorf("guest agent = installed=%v running=%v, want true/true", info.GuestAgentInstalled, info.GuestAgentRunning)
	}
	if !info.MaintenanceChecked || info.OnHostMaintenance != "MIGRATE" || info.ActiveMaintenance != "" || info.Preemptible {
		t.Errorf("maintenance = %+v, want checked/MIGRATE/no-active/not-preemptible", info)
	}
	if !info.OSLoginChecked || !info.OSLoginEnabled {
		t.Errorf("oslogin = checked=%v enabled=%v, want true/true", info.OSLoginChecked, info.OSLoginEnabled)
	}
	if !info.TimeSyncChecked || !info.UsesMetadataNTP {
		t.Errorf("timesync = checked=%v uses=%v, want true/true", info.TimeSyncChecked, info.UsesMetadataNTP)
	}
}

// ── gcpGuestAgentState ────────────────────────────────────────────────────────

func TestGcpGuestAgentState_InstalledAndRunning(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/google_guest_agent": []byte("/usr/bin/google_guest_agent"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "google-guest-agent"}, "active\n", 0)
	})
	installed, running := gcpGuestAgentState()
	if !installed || !running {
		t.Errorf("installed=%v running=%v, want true/true", installed, running)
	}
}

func TestGcpGuestAgentState_InstalledNotRunning(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/google_guest_agent": []byte("/usr/bin/google_guest_agent"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "google-guest-agent"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "google-accounts-daemon"}, "inactive\n", 3)
	})
	installed, running := gcpGuestAgentState()
	if !installed || running {
		t.Errorf("installed=%v running=%v, want true/false", installed, running)
	}
}

func TestGcpGuestAgentState_InstalledViaMarkerFile(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutStat("/usr/bin/google_guest_agent", source.FileMeta{})
		b.PutCmdNotFound("systemctl", []string{"is-active", "google-guest-agent"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "google-accounts-daemon"})
	})
	installed, running := gcpGuestAgentState()
	if !installed || running {
		t.Errorf("installed=%v running=%v, want true/false", installed, running)
	}
}

func TestGcpGuestAgentState_NotInstalled(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	installed, running := gcpGuestAgentState()
	if installed || running {
		t.Errorf("installed=%v running=%v, want false/false", installed, running)
	}
}

// ── gcpMaintenance ────────────────────────────────────────────────────────────

func TestGcpMaintenance_Success(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/scheduling/on-host-maintenance": []byte("terminate"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/scheduling/preemptible":         []byte("TRUE"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/maintenance-event":              []byte("host_maintenance_in_progress"),
	}, nil, nil)
	checked, policy, active, preemptible := gcpMaintenance(context.Background())
	if !checked || policy != "TERMINATE" || active != "host_maintenance_in_progress" || !preemptible {
		t.Errorf("gcpMaintenance() = checked=%v policy=%q active=%q preemptible=%v, want true/TERMINATE/host_maintenance_in_progress/true",
			checked, policy, active, preemptible)
	}
}

func TestGcpMaintenance_MaintenanceEventNone(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/scheduling/on-host-maintenance": []byte("MIGRATE"),
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/maintenance-event":              []byte("NONE"),
	}, nil, nil)
	checked, policy, active, _ := gcpMaintenance(context.Background())
	if !checked || policy != "MIGRATE" || active != "" {
		t.Errorf("gcpMaintenance() = checked=%v policy=%q active=%q, want true/MIGRATE/empty", checked, policy, active)
	}
}

func TestGcpMaintenance_MetadataUnreachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	checked, policy, active, preemptible := gcpMaintenance(context.Background())
	if checked || policy != "" || active != "" || preemptible {
		t.Errorf("gcpMaintenance() = %v/%q/%q/%v, want false/empty/empty/false", checked, policy, active, preemptible)
	}
}

// ── gcpOSLogin ────────────────────────────────────────────────────────────────

func TestGcpOSLogin_InstanceAttribute(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/instance/attributes/enable-oslogin": []byte("TRUE"),
	}, nil, nil)
	checked, enabled := gcpOSLogin(context.Background())
	if !checked || !enabled {
		t.Errorf("checked=%v enabled=%v, want true/true", checked, enabled)
	}
}

func TestGcpOSLogin_FallsBackToProjectAttribute(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds/http://metadata.google.internal/computeMetadata/v1/project/attributes/enable-oslogin": []byte("true"),
	}, nil, nil)
	checked, enabled := gcpOSLogin(context.Background())
	if !checked || !enabled {
		t.Errorf("checked=%v enabled=%v, want true/true (project fallback)", checked, enabled)
	}
}

func TestGcpOSLogin_NeitherAvailable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	checked, enabled := gcpOSLogin(context.Background())
	if checked || enabled {
		t.Errorf("checked=%v enabled=%v, want false/false", checked, enabled)
	}
}

// ── gcpTimeSyncConfigured ─────────────────────────────────────────────────────

func TestGcpTimeSyncConfigured_UsesMetadataServer(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/chrony.conf", []byte("server 169.254.169.254 iburst\n"))
	})
	checked, uses := gcpTimeSyncConfigured()
	if !checked || !uses {
		t.Errorf("checked=%v uses=%v, want true/true", checked, uses)
	}
}

func TestGcpTimeSyncConfigured_ConfiguredButNotMetadata(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/chrony.conf", []byte("server time.google.com iburst\n"))
	})
	checked, uses := gcpTimeSyncConfigured()
	if !checked || uses {
		t.Errorf("checked=%v uses=%v, want true/false", checked, uses)
	}
}

func TestGcpTimeSyncConfigured_ViaConfD(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/etc/chrony/conf.d/*.conf", []string{"/etc/chrony/conf.d/gcp.conf"})
		b.PutFile("/etc/chrony/conf.d/gcp.conf", []byte("server metadata.google.internal iburst\n"))
	})
	checked, uses := gcpTimeSyncConfigured()
	if !checked || !uses {
		t.Errorf("checked=%v uses=%v, want true/true (via conf.d glob)", checked, uses)
	}
}

func TestGcpTimeSyncConfigured_NoFilesFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	checked, uses := gcpTimeSyncConfigured()
	if checked || uses {
		t.Errorf("checked=%v uses=%v, want false/false", checked, uses)
	}
}
