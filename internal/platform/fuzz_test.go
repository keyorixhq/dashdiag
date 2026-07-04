package platform

import "testing"

// FuzzParseOSRelease guards the /etc/os-release parser — the input platform.Detect
// reads on every collector run to decide distro family, package manager hints, and
// log paths threaded through nearly every verdict. Unlike the SMART/NVMe fuzzers
// (which catch numeric out-of-range garbage becoming a false verdict), this parser
// has no numeric path beyond an error-checked strconv.Atoi, so the invariant here
// is narrower: arbitrary/malformed os-release content must never panic
// parseOSRelease or setLogPaths, whatever distro family it lands on.
func FuzzParseOSRelease(f *testing.F) {
	seeds := []string{
		rhel101,
		debian12,
		ubuntu2404,
		sles156,
		opensuseLeap16,
		nixos2505,
		steamos37,
		almalinux94,
		rocky10,
		"",
		"=",
		"====",
		"ID",
		"ID=",
		"ID=\"\n\"",
		"VERSION_ID=" + string([]byte{0xff, 0xfe, 0x00}),
		"VERSION_ID=99999999999999999999999999999999",
		"VERSION_ID=-5.-3",
		"VERSION_ID=.",
		"ID=steamos\nVARIANT_ID=steamdeck\nVERSION_ID=",
		"\x00\x00\x00",
		"ID=rhel\n\n\n\nVERSION_ID=10\n\n\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		p := Profile{OS: "linux"}
		parseOSRelease(&p, content)
		setLogPaths(&p)
	})
}
