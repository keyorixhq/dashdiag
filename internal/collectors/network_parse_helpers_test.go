package collectors

import (
	"math"
	"testing"
)

func TestParseSysPingOutput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		in          string
		wantMS      float64
		wantLossPct float64
		wantOK      bool
	}{
		{
			name:        "empty string",
			in:          "",
			wantMS:      -1,
			wantLossPct: 100,
			wantOK:      false,
		},
		{
			name: "typical linux ping 0% loss",
			in: "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n" +
				"3 packets transmitted, 3 received, 0% packet loss, time 2002ms\n" +
				"rtt min/avg/max/mdev = 0.585/0.660/0.806/0.102 ms\n",
			wantMS:      0.660,
			wantLossPct: 0,
			wantOK:      true,
		},
		{
			name:        "100% loss no rtt line",
			in:          "3 packets transmitted, 0 received, 100% packet loss, time 2002ms\n",
			wantLossPct: 100,
			wantOK:      false,
		},
		{
			name: "50% loss with rtt line",
			in: "2 packets transmitted, 1 received, 50% packet loss\n" +
				"rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms\n",
			wantMS:      2.0,
			wantLossPct: 50,
			wantOK:      true,
		},
		{
			name: "macos style ping output",
			in: "3 packets transmitted, 3 packets received, 0.0% packet loss\n" +
				"round-trip min/avg/max/stddev = 0.500/1.000/1.500/0.408 ms\n",
			wantMS:      1.000,
			wantLossPct: 0,
			wantOK:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ms, lossPct, ok := parseSysPingOutput(tc.in)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if lossPct != tc.wantLossPct {
				t.Errorf("lossPct = %v, want %v", lossPct, tc.wantLossPct)
			}
			if tc.wantOK && math.Abs(ms-tc.wantMS) > 0.001 {
				t.Errorf("ms = %v, want %v", ms, tc.wantMS)
			}
		})
	}
}

func TestJitterStddev(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []float64
		want float64
	}{
		{name: "empty slice", in: []float64{}, want: 0},
		{name: "single element", in: []float64{5.0}, want: 0},
		{name: "identical values zero variance", in: []float64{10, 10}, want: 0.0},
		{name: "two values symmetric", in: []float64{0, 2}, want: 1.0},
		{name: "textbook population stddev", in: []float64{2, 4, 4, 4, 5, 5, 7, 9}, want: 2.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := jitterStddev(tc.in)
			if math.Abs(got-tc.want) > 0.001 {
				t.Errorf("jitterStddev(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
