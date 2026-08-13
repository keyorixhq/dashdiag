//go:build linux

package collectors

import (
	"testing"
	"unicode/utf8"
)

// Fuzz harness over the parsers added/touched this session (cloud IMDS JSON, Hyper-V
// balloon dmesg, ENA SRD counters, prior-boot OOM). Each asserts no panic AND a
// plausibility invariant — the technique that surfaced 7 real NaN/overflow/negative bugs
// in the smartctl/NVMe parsers (#372/#373). A crasher found here is written to
// testdata/fuzz and becomes a CI regression guard.

func FuzzParseHVBalloonMaxMB(f *testing.F) {
	f.Add("hv_balloon: Max. dynamic memory size: 8192 MB")
	f.Add("hv_balloon: Max. dynamic memory size: 99999999999999999999999 MB")
	f.Add("hv_balloon: Max. dynamic memory size: -5 MB")
	f.Add("garbage\x00\xff")
	f.Fuzz(func(t *testing.T, s string) {
		if got := parseHVBalloonMaxMB(s); got < 0 {
			t.Fatalf("parseHVBalloonMaxMB(%q) = %d, must never be negative", s, got)
		}
	})
}

func FuzzParseAzureStorageProfile(f *testing.F) {
	f.Add(`{"osDisk":{"name":"os","caching":"ReadWrite"},"dataDisks":[{"name":"d0","lun":"0","caching":"None"}]}`)
	f.Add(`{"osDisk":{"caching":"ReadWrite"},"dataDisks":[{"lun":"-9","caching":"ReadWrite"}]}`)
	f.Add(`{"dataDisks":[{"lun":"99999999999999999999","caching":""}]}`)
	f.Add(`not json`)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, body string) {
		checked, disks := parseAzureStorageProfile(body)
		if !checked {
			if disks != nil {
				t.Fatalf("unchecked profile must return nil disks, got %+v", disks)
			}
			return
		}
		// Checked => at least the OS disk, and no disk may carry a negative LUN (a
		// hostile IMDS LUN like "-9" must not surface as a real negative LUN).
		if len(disks) == 0 {
			t.Fatalf("checked profile with no disks: %q", body)
		}
		for _, d := range disks {
			if d.Lun < 0 {
				t.Fatalf("disk %+v has negative LUN from body %q", d, body)
			}
		}
	})
}

func FuzzParseAzureScheduledEvents(f *testing.F) {
	f.Add(`{"Events":[{"EventType":"Reboot","EventStatus":"Scheduled","NotBefore":"now"}]}`)
	f.Add(`{"Events":[{"EventType":"","EventStatus":"Scheduled"}]}`)
	f.Add(`{"Events":[]}`)
	f.Add("{\"Events\":[{\"EventType\":\" \x00\xff\"}]}")
	f.Add(`garbage`)
	f.Fuzz(func(t *testing.T, body string) {
		pending, details := parseAzureScheduledEvents(body)
		if pending && details == "" {
			t.Fatalf("pending event with empty details from body %q", body)
		}
		if !utf8.ValidString(details) {
			t.Fatalf("details is not valid UTF-8 from body %q", body)
		}
	})
}

func FuzzENASRDActive(f *testing.F) {
	f.Add("     ena_srd_tx_pkts: 42\n     ena_srd_rx_pkts: 0\n")
	f.Add("ena_srd_tx_pkts: 99999999999999999999999\n")
	f.Add("ena_srd_tx_pkts: -1\n")
	f.Add("\x00\xff: nope")
	f.Fuzz(func(t *testing.T, out string) {
		_ = enaSRDActive(out) // must not panic; bool result needs no invariant
	})
}

func FuzzParseOOMEvents(f *testing.F) {
	f.Add("2026-06-22T10:00:00+00:00 host kernel: Out of memory: Killed process 123 (mysqld)")
	f.Add("Killed process -1 (\x00) ")
	f.Add("Out of memory\x00\xff\xfe garbage")
	f.Fuzz(func(t *testing.T, out string) {
		events, _ := parseOOMEvents(out)
		for _, e := range events {
			if e.PID < 0 {
				t.Fatalf("OOM event has negative PID %d from %q", e.PID, out)
			}
		}
	})
}
