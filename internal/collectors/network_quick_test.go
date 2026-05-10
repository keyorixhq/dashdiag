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
			if gw.GatewayIP != tc.wantGW {
				t.Errorf("gateway: got %q, want %q", gw.GatewayIP, tc.wantGW)
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
	if gw.GatewayIP != "192.168.1.1" {
		t.Errorf("gateway: got %q, want 192.168.1.1", gw.GatewayIP)
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

func TestParsePingGroupRange(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		wantLow  int
		wantHigh int
		wantOK   bool
	}{
		{"ubuntu default — no groups allowed", "1\t0\n", 0, 0, false},
		{"ubuntu default with spaces", "1 0\n", 0, 0, false},
		{"all users allowed", "0 2147483647\n", 0, 2147483647, true},
		{"narrow allow range", "100 200\n", 100, 200, true},
		{"single GID allowed", "1000 1000\n", 1000, 1000, true},
		{"empty", "", 0, 0, false},
		{"single field", "100", 0, 0, false},
		{"three fields", "1 2 3", 0, 0, false},
		{"non-numeric", "foo bar", 0, 0, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			low, high, ok := parsePingGroupRange(tc.input)
			if ok != tc.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if tc.wantOK && (low != tc.wantLow || high != tc.wantHigh) {
				t.Errorf("range: got [%d,%d], want [%d,%d]", low, high, tc.wantLow, tc.wantHigh)
			}
		})
	}
}

func TestParseCapEffHasNetRaw(t *testing.T) {
	t.Parallel()
	// CAP_NET_RAW is bit 13 = 0x2000.
	// Real /proc/self/status formatting uses tab between key and value.
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "root with full caps including CAP_NET_RAW",
			input: "Name:\troot\nCapEff:\t000001ffffffffff\n",
			want:  true,
		},
		{
			name:  "non-root with no caps",
			input: "Name:\tandrei\nCapEff:\t0000000000000000\n",
			want:  false,
		},
		{
			name:  "only CAP_NET_RAW set",
			input: "CapEff:\t0000000000002000\n",
			want:  true,
		},
		{
			name:  "CAP_NET_BIND_SERVICE (10) set, NET_RAW not",
			input: "CapEff:\t0000000000000400\n",
			want:  false,
		},
		{
			name:  "missing CapEff line",
			input: "Name:\troot\n",
			want:  false,
		},
		{
			name:  "malformed CapEff value",
			input: "CapEff:\tnot-a-hex-number\n",
			want:  false,
		},
		{
			name:  "empty input",
			input: "",
			want:  false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseCapEffHasNetRaw(tc.input)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
