package collectors

import (
	"os"
	"strings"
	"testing"
)

func TestParseGatewayLinux(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		input  string
		wantGW string
	}{
		{
			name: "standard default route",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
			wantGW: "192.168.1.1",
		},
		{
			name: "different gateway",
			input: "Iface\tDestination\tGateway\tFlags\n" +
				"eth0\t00000000\t010AA8C0\t0003\n",
			wantGW: "192.168.10.1",
		},
		{
			name: "no default route",
			input: "Iface\tDestination\tGateway\tFlags\n" +
				"eth0\t0001A8C0\t00000000\t0001\n",
			wantGW: "",
		},
		{
			name:   "empty input",
			input:  "",
			wantGW: "",
		},
		{
			name:   "header only",
			input:  "Iface\tDestination\tGateway\tFlags\n",
			wantGW: "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gw := parseGatewayLinux(strings.NewReader(tc.input))
			if gw != tc.wantGW {
				t.Errorf("gateway: got %q, want %q", gw, tc.wantGW)
			}
		})
	}
}

func TestParseGatewayLinux_FixtureFile(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/network/proc_net_route.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	gw := parseGatewayLinux(f)
	if gw != "192.168.1.1" {
		t.Errorf("gateway: got %q, want 192.168.1.1", gw)
	}
}

func TestShouldSkipIface(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		ifaceName string
		want      bool
	}{
		{"loopback", "lo", true},
		{"docker0", "docker0", true},
		{"veth prefix", "veth0a1b2c", true},
		{"br- prefix", "br-abc123", true},
		{"virbr prefix", "virbr0", true},
		{"eth0 allowed", "eth0", false},
		{"en0 allowed", "en0", false},
		{"wlan0 allowed", "wlan0", false},
		{"ens3 allowed", "ens3", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := shouldSkipIface(tc.ifaceName)
			if got != tc.want {
				t.Errorf("shouldSkipIface(%q): got %v, want %v", tc.ifaceName, got, tc.want)
			}
		})
	}
}
