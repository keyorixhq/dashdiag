package collectors

import (
	"strings"
	"testing"
)

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

	got := parseBlameSlowUnits(openSUSEBlame)

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
