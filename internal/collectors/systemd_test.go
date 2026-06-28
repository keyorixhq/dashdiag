package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Per-connection socket-activated sshd instances (sshd@.service template, the
// default on Photon/Fedora) go "failed" when a connection drops before auth — a
// port scan, an LB/TCP health probe, kex_exchange_identification. They are not a
// daemon fault and must be filtered out of the failed-units verdict via the
// template-instance collapsing, while the real sshd.service is kept. (Found live
// on VMware Photon OS, where dsd health raised 4 false CRITs from probe-closed
// connections.)
func TestFilterUnitsDropsPerConnectionSSHD(t *testing.T) {
	t.Parallel()
	units := []string{
		"sshd@0-192.168.30.229:22-192.168.30.10:52934.service",
		"sshd@1-192.168.30.229:22-192.168.30.10:42008.service",
		"sshd.service",    // the real daemon — must be kept
		"my-real.service", // unrelated genuine failure — must be kept
	}
	got := filterUnits(units, cloudInitUnits)
	for _, u := range got {
		if strings.HasPrefix(u, "sshd@") {
			t.Errorf("per-connection sshd instance leaked through filter: %q", u)
		}
	}
	if !contains(got, "sshd.service") {
		t.Error("real sshd.service daemon unit was wrongly filtered")
	}
	if !contains(got, "my-real.service") {
		t.Error("unrelated genuine failed unit was wrongly filtered")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// systemd ships systemd-sysupdate.timer enabled, but with no transfer
// definitions configured the service exits 1 ("No transfer definitions found")
// every firing and sits permanently "failed" — a benign default state (verified
// live on VMware Photon OS 5.0, where dsd false-CRIT'd on it). Suppress ONLY when
// unconfigured; a real update failure (transfers present) must survive.
func TestDropSysupdateIf(t *testing.T) {
	t.Parallel()
	// BOTH sysupdate units (apply + reboot variant) fail "No transfer definitions
	// found" when unconfigured — the -reboot sibling was missed at first and
	// false-CRIT'd live on Photon, so both must be covered.
	failed := []string{"systemd-sysupdate.service", "systemd-sysupdate-reboot.service", "real.service"}

	// Unconfigured (no transfers) → both benign units dropped; real failure kept.
	got := dropSysupdateIf(append([]string(nil), failed...), true)
	if containsUnit(got, "systemd-sysupdate.service") || containsUnit(got, "systemd-sysupdate-reboot.service") {
		t.Errorf("unconfigured sysupdate units (incl. -reboot) should be suppressed, got %v", got)
	}
	if !containsUnit(got, "real.service") {
		t.Error("a genuine failed unit must never be suppressed")
	}

	// Configured (transfers present) → a sysupdate failure is real, keep both.
	got = dropSysupdateIf(append([]string(nil), failed...), false)
	if !containsUnit(got, "systemd-sysupdate.service") || !containsUnit(got, "systemd-sysupdate-reboot.service") {
		t.Error("configured sysupdate failures must be kept (could be a real update failure)")
	}
}

// `dsd services deep` must suppress the same failed-unit noise the health
// SystemdCollector does, so the two never give opposite verdicts on the same host
// (observed live on Photon: services deep CRIT'd "47 failed units" — transient
// sshd@<conn> instances + cloud-config — while health read Systemd OK).
func TestFilterBenignFailedUnits(t *testing.T) {
	t.Parallel()
	units := []models.SystemdUnit{
		{Name: "sshd@0-10.0.0.1:22-10.0.0.2:5000.service"},
		{Name: "sshd@1-10.0.0.1:22-10.0.0.2:5001.service"},
		{Name: "cloud-config.service"},
		{Name: "my-app.service"}, // a genuine failure — must survive
	}
	got := filterBenignFailedUnits(units)
	if len(got) != 1 || got[0].Name != "my-app.service" {
		t.Fatalf("want only my-app.service to survive, got %+v", got)
	}
}

func TestParseUnitList(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		input     string
		wantUnits []string
	}{
		{
			name:      "single failed unit",
			input:     "nginx.service       loaded failed failed The nginx HTTP server\n",
			wantUnits: []string{"nginx.service"},
		},
		{
			name: "multiple units",
			input: "sshd.service        loaded failed failed OpenSSH server\n" +
				"cron.service        loaded failed failed Cron daemon\n",
			wantUnits: []string{"sshd.service", "cron.service"},
		},
		{
			name:      "empty output",
			input:     "",
			wantUnits: nil,
		},
		{
			name:      "lines without dots are skipped",
			input:     "0 units listed\n",
			wantUnits: nil,
		},
		{
			name:      "blank lines skipped",
			input:     "\nnginx.service loaded failed failed nginx\n\n",
			wantUnits: []string{"nginx.service"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseUnitList(strings.NewReader(tc.input))
			if len(got) != len(tc.wantUnits) {
				t.Fatalf("unit count: got %d %v, want %d %v", len(got), got, len(tc.wantUnits), tc.wantUnits)
			}
			for i, u := range tc.wantUnits {
				if got[i] != u {
					t.Errorf("unit[%d]: got %q, want %q", i, got[i], u)
				}
			}
		})
	}
}

func TestParseBlameSlowUnits(t *testing.T) {
	t.Parallel()

	// Real `systemd-analyze blame` output from the openSUSE Leap 16 test VM
	// (192.168.10.56). The slowest line uses a multi-token duration
	// ("1min 52.470s") — earlier code took fields[0]="1min" as the duration and
	// fields[1]="52.470s" as the unit name, mangling both. cloud-final.service is
	// also a cloud-init unit that must be filtered once parsed correctly.
	const openSUSEBlame = `1min 52.470s cloud-final.service
     23.856s sys-devices-pnp0-00:00-00:00:0-00:00:0.0-tty-ttyS0.device
     23.853s dev-vport2p1.device
      6.200s postgresql.service
        850ms chronyd.service`

	got := parseBlameSlowUnits(openSUSEBlame, nil)

	// After filtering, only real slow SERVICE units (≥5s) survive:
	//   - cloud-final.service (slowest) → dropped (cloud-init infrastructure)
	//   - the two .device units (ttyS0 / vport at ~24s) → dropped: these are the
	//     virtio/serial-console device-timeout artifacts that show up on virtually
	//     every VM. Flagging them was first-run noise on the (all-VM) pilot fleet.
	//   - chronyd.service (850ms) → dropped (< 5s)
	want := []struct {
		name string
		dur  float64
	}{
		{"postgresql.service", 6.200},
	}
	if len(got) != len(want) {
		t.Fatalf("unit count: got %d %+v, want %d", len(got), got, len(want))
	}
	for i, w := range want {
		if got[i].Name != w.name {
			t.Errorf("unit[%d] name: got %q, want %q", i, got[i].Name, w.name)
		}
		if got[i].Duration < w.dur-0.01 || got[i].Duration > w.dur+0.01 {
			t.Errorf("unit[%d] duration: got %.3f, want %.3f", i, got[i].Duration, w.dur)
		}
	}

	// Regression guards:
	for _, u := range got {
		// the mangled multi-token duration must never resurface as a unit name
		if u.Name == "52.470s" || u.Name == "1min" {
			t.Errorf("duration token leaked as unit name: %q", u.Name)
		}
		// no non-service unit (.device/.mount/etc.) may appear in the slow-boot list
		if isNonServiceBlameUnit(u.Name) {
			t.Errorf("non-service unit leaked into slow-boot units: %q", u.Name)
		}
	}
}

// TestParseBlameSlowUnitsExcludesTimers pins the fix for the universal
// Debian/Ubuntu false-WARN: `systemd-analyze blame` lists timer-triggered jobs
// (apt-daily-upgrade.service runs ~28s post-boot via apt-daily-upgrade.timer) by
// activation duration, but they never gated boot. Found on the real VMware k3s
// tenant, where blame's top two entries were both apt-daily timers.
func TestParseBlameSlowUnitsExcludesTimers(t *testing.T) {
	t.Parallel()

	// Verbatim top of `systemd-analyze blame` from the tenant (Ubuntu 24.04):
	// the two apt-daily timers outrank the real service, and both exceed the
	// 12.2s total boot time — proof they ran async, post-boot.
	const blame = `27.945s apt-daily-upgrade.service
23.587s apt-daily.service
14.447s k3s.service
 3.348s motd-news.service`

	// Exclude timer-triggered units (what the production excluder detects).
	timers := map[string]bool{
		"apt-daily-upgrade.service": true,
		"apt-daily.service":         true,
	}
	got := parseBlameSlowUnits(blame, func(u string) bool { return timers[u] })

	if len(got) != 1 || got[0].Name != "k3s.service" {
		t.Fatalf("want only k3s.service after timer exclusion, got %+v", got)
	}
	for _, u := range got {
		if timers[u.Name] {
			t.Errorf("timer-triggered job leaked into slow-boot units: %q", u.Name)
		}
	}

	// Without the excluder (nil), the legacy behaviour returns the timer jobs —
	// confirms the fix is the excluder, not an unrelated parse change.
	legacy := parseBlameSlowUnits(blame, nil)
	if len(legacy) == 0 || legacy[0].Name != "apt-daily-upgrade.service" {
		t.Fatalf("nil excluder should preserve legacy (unfiltered) output, got %+v", legacy)
	}
}
