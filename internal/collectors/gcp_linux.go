//go:build linux

package collectors

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// GCPCollector reports guest-side health for a Linux VM on Google Compute Engine: the
// NIC driver (gVNIC vs virtio), the Google guest agent, the host-maintenance policy,
// OS Login, and the time source. All work is gated behind GCPGuestAvailable() so it is
// zero-cost and silent on every non-GCP host. Scope is strictly guest-side, no
// authenticated GCP API — sysfs, local config/service state, and the unauthenticated
// link-local metadata server only.
type GCPCollector struct{}

func NewGCPCollector() *GCPCollector { return &GCPCollector{} }

func (c *GCPCollector) Name() string           { return "GCP" }
func (c *GCPCollector) Timeout() time.Duration { return 3 * time.Second }

// GCPGuestAvailable reports whether this host is a Linux VM on Google Compute Engine.
// Cheap gate (same shape as AWSGuestAvailable/AzureGuestAvailable): world-readable DMI
// strings, no root, no command execution. "Google Compute Engine" in product_name is
// the documented marker; "Google" in sys_vendor is the secondary one.
func GCPGuestAvailable() bool {
	return isGCPGuest(
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "product_name")),
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "sys_vendor")),
	)
}

// isGCPGuest matches GCE's DMI signature. Kept in sync with platform.detectCloudEnvironment.
func isGCPGuest(productName, sysVendor string) bool {
	hay := strings.ToLower(productName + " " + sysVendor)
	return strings.Contains(hay, "google compute") || strings.Contains(hay, "google")
}

// gcpMetadataHeader is required on every metadata-server request; without it the
// server returns 403.
var gcpMetadataHeader = map[string]string{"Metadata-Flavor": "Google"}

func (c *GCPCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.GCPInfo{IsGCP: true}

	info.NICDriver, info.UsesGVNIC = gcpNICDriver("/sys/class/net")
	info.GuestAgentInstalled, info.GuestAgentRunning = gcpGuestAgentState()
	info.MaintenanceChecked, info.OnHostMaintenance, info.ActiveMaintenance, info.Preemptible = gcpMaintenance(ctx)
	info.OSLoginChecked, info.OSLoginEnabled = gcpOSLogin(ctx)
	info.TimeSyncChecked, info.UsesMetadataNTP = gcpTimeSyncConfigured()

	return info, nil
}

// ---------- NIC driver (gVNIC vs virtio) ----------

// gcpNICDriver returns the primary NIC's driver and whether any gVNIC (gve) interface
// is present. The primary NIC is the alphabetically-first non-loopback interface — on
// GCE this is eth0/ens4, deterministic enough for a recognition line.
func gcpNICDriver(netDir string) (driver string, usesGVNIC bool) {
	drivers, _ := collectNICDrivers(netDir)
	if len(drivers) == 0 {
		return "", false
	}
	names := make([]string, 0, len(drivers))
	for iface := range drivers {
		names = append(names, iface)
		if strings.EqualFold(drivers[iface], "gve") {
			usesGVNIC = true
		}
	}
	sort.Strings(names)
	return drivers[names[0]], usesGVNIC
}

// ---------- Google guest agent ----------

// gcpGuestAgentState reports whether the Google guest agent is installed and running.
// Installed-but-not-running is the actionable case (SSH-key / OS-Login propagation and
// account management silently break); not-installed is silent (some minimal images run
// without it). The modern unit is google-guest-agent; older images split it into
// google-accounts-daemon / google-network-daemon.
func gcpGuestAgentState() (installed, running bool) {
	for _, bin := range []string{"google_guest_agent", "google_osconfig_agent"} {
		if _, err := lookPath(bin); err == nil {
			installed = true
		}
	}
	for _, p := range []string{
		"/usr/bin/google_guest_agent",
		"/usr/lib/systemd/system/google-guest-agent.service",
		"/lib/systemd/system/google-guest-agent.service",
	} {
		if fileExists(p) {
			installed = true
			break
		}
	}
	if !installed {
		return false, false
	}
	for _, unit := range []string{"google-guest-agent", "google-accounts-daemon"} {
		if out, err := runCmd(context.Background(), "systemctl", "is-active", unit); err == nil &&
			strings.TrimSpace(out) == "active" {
			return true, true
		}
	}
	return true, false
}

// ---------- Host-maintenance behaviour ----------

// gcpMaintenance reads the host-maintenance policy and any in-progress event from the
// metadata server. checked is false on any metadata error so an unread policy never
// reads as "safe". onHostMaintenance is MIGRATE (safe default) or TERMINATE; active is
// the maintenance-event value when one is not NONE.
func gcpMaintenance(ctx context.Context) (checked bool, onHostMaintenance, active string, preemptible bool) {
	const base = "http://metadata.google.internal/computeMetadata/v1/instance/"
	policy, err := imdsGet(ctx, base+"scheduling/on-host-maintenance", gcpMetadataHeader)
	if err != nil {
		return false, "", "", false
	}
	checked = true
	onHostMaintenance = strings.ToUpper(strings.TrimSpace(policy))

	if pre, e := imdsGet(ctx, base+"scheduling/preemptible", gcpMetadataHeader); e == nil {
		preemptible = strings.EqualFold(strings.TrimSpace(pre), "true")
	}
	if ev, e := imdsGet(ctx, base+"maintenance-event", gcpMetadataHeader); e == nil {
		if v := strings.TrimSpace(ev); v != "" && !strings.EqualFold(v, "NONE") {
			active = v
		}
	}
	return checked, onHostMaintenance, active, preemptible
}

// ---------- OS Login ----------

// gcpOSLogin reports whether OS Login is enabled, reading the instance attribute first
// then falling back to the project attribute (instance overrides project). checked is
// false when neither attribute could be read.
func gcpOSLogin(ctx context.Context) (checked, enabled bool) {
	const base = "http://metadata.google.internal/computeMetadata/v1/"
	for _, path := range []string{"instance/attributes/enable-oslogin", "project/attributes/enable-oslogin"} {
		v, err := imdsGet(ctx, base+path, gcpMetadataHeader)
		if err != nil {
			continue
		}
		return true, strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false, false
}

// ---------- Time sync ----------

// gcpTimeSyncConfigured reports whether the NTP client points at GCP's metadata server
// (metadata.google.internal / 169.254.169.254), GCP's recommended time source. checked
// is false when no chrony/timesyncd config was found to read.
func gcpTimeSyncConfigured() (checked, uses bool) {
	files := []string{
		"/etc/chrony.conf",
		"/etc/chrony/chrony.conf",
		"/etc/systemd/timesyncd.conf",
	}
	for _, pat := range []string{"/etc/chrony/conf.d/*.conf", "/etc/chrony/sources.d/*.sources"} {
		if matches, err := activeSource.Glob(pat); err == nil {
			files = append(files, matches...)
		}
	}
	for _, f := range files {
		body := readFileTrimmedLocal(f)
		if body == "" {
			continue
		}
		checked = true
		low := strings.ToLower(body)
		if strings.Contains(low, "metadata.google.internal") || strings.Contains(low, "169.254.169.254") {
			return true, true
		}
	}
	return checked, false
}
