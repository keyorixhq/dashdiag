package collectors

import "testing"

// x86 /proc/cpuinfo emits BOTH a "processor" and a "model name" line per logical
// CPU. The thread count must reflect logical CPUs once, not twice.
func TestParseProcCPUInfo_x86NoDoubleCount(t *testing.T) {
	const data = `processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
cpu MHz		: 1992.000
cpu cores	: 4

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
cpu MHz		: 1992.000
cpu cores	: 4

processor	: 2
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
cpu MHz		: 1992.000
cpu cores	: 4

processor	: 3
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
cpu MHz		: 1992.000
cpu cores	: 4
`
	got := parseProcCPUInfo(data)
	if got.threads != 4 {
		t.Errorf("threads = %d, want 4 (one per 'processor' line, not doubled by 'model name')", got.threads)
	}
	if got.cores != 4 {
		t.Errorf("cores = %d, want 4", got.cores)
	}
	if got.model != "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz" {
		t.Errorf("model = %q, want Intel i7-8550U", got.model)
	}
	if got.freqMHz != 1992.0 {
		t.Errorf("freqMHz = %g, want 1992", got.freqMHz)
	}
}

// ARM /proc/cpuinfo has "processor" lines but no "model name"; with an implementer
// but no recognized part, the model is the vendor + arch (no redundant "ARM ARM").
func TestParseProcCPUInfo_armImplementerFallback(t *testing.T) {
	const data = `processor	: 0
BogoMIPS	: 108.00
CPU implementer	: 0x41
CPU architecture: 8

processor	: 1
BogoMIPS	: 108.00
CPU implementer	: 0x41
`
	got := parseProcCPUInfo(data)
	if got.threads != 2 {
		t.Errorf("threads = %d, want 2", got.threads)
	}
	if got.model != "ARM (aarch64)" {
		t.Errorf("model = %q, want %q", got.model, "ARM (aarch64)")
	}
}

// Server ARM (Ampere Altra / AWS Graviton2) reports a Neoverse-N1 core via the
// implementer+part codes — the model should name the core (the useful server ID,
// since there is no "model name" line and no Hardware field).
func TestParseProcCPUInfo_armNeoverseN1(t *testing.T) {
	const data = `processor	: 0
BogoMIPS	: 50.00
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x3
CPU part	: 0xd0c
CPU revision	: 1

processor	: 1
CPU implementer	: 0x41
CPU part	: 0xd0c
`
	got := parseProcCPUInfo(data)
	if got.threads != 2 {
		t.Errorf("threads = %d, want 2", got.threads)
	}
	if got.model != "ARM Neoverse-N1 (aarch64)" {
		t.Errorf("model = %q, want %q", got.model, "ARM Neoverse-N1 (aarch64)")
	}
}

// AmpereOne reports the Ampere implementer (0xc0) with its own part space.
func TestParseProcCPUInfo_ampereOne(t *testing.T) {
	const data = `processor	: 0
CPU implementer	: 0xc0
CPU part	: 0xac3
`
	got := parseProcCPUInfo(data)
	if got.model != "Ampere AmpereOne (aarch64)" {
		t.Errorf("model = %q, want %q", got.model, "Ampere AmpereOne (aarch64)")
	}
}

// ARMv8.5 server core reports PAC/MTE support via the "Features" line — parsed
// verbatim (not tokenized here) so callers can token-match specific flags.
func TestParseProcCPUInfo_armFeatures(t *testing.T) {
	t.Parallel()
	const data = `processor	: 0
CPU implementer	: 0x41
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm paca pacg mte mte3
`
	got := parseProcCPUInfo(data)
	if got.features != "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm paca pacg mte mte3" {
		t.Errorf("features = %q, unexpected", got.features)
	}
	if !hasFeature(got.features, "mte") {
		t.Error("hasFeature(features, \"mte\") = false, want true")
	}
	if hasFeature(got.features, "sve") {
		t.Error("hasFeature(features, \"sve\") = true, want false — sve is not in this Features line")
	}
}

// hasFeature must match whole tokens only — a flag name that merely contains
// another flag as a substring (e.g. hypothetical "mteplus") must not
// false-positive a plain "mte" lookup.
func TestHasFeature_ExactTokenMatch(t *testing.T) {
	t.Parallel()
	if hasFeature("fp asimd mteplus evtstrm", "mte") {
		t.Error("hasFeature must not substring-match \"mteplus\" against \"mte\"")
	}
	if !hasFeature("fp asimd mte evtstrm", "mte") {
		t.Error("hasFeature must match \"mte\" as a whole token")
	}
	if hasFeature("", "mte") {
		t.Error("hasFeature on empty features string must be false")
	}
}

// TestArmImplementerName guards the vendor-code lookup table and the
// unknown-code fallback (return the code itself, unmapped).
func TestArmImplementerName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code string
		want string
	}{
		{"0x41", "ARM"},
		{"0x42", "Broadcom"},
		{"0x43", "Cavium"},
		{"0x44", "DEC"},
		{"0x48", "HiSilicon"},
		{"0x49", "Infineon"},
		{"0x4d", "Motorola/Freescale"},
		{"0x4e", "NVIDIA"},
		{"0x50", "APM"},
		{"0x51", "Qualcomm"},
		{"0x53", "Samsung"},
		{"0x56", "Marvell"},
		{"0x61", "Apple"},
		{"0x66", "Faraday"},
		{"0x69", "Intel"},
		{"0x70", "Phytium"},
		{"0xc0", "Ampere"},
		{"0X41", "ARM"},  // case-insensitive
		{"0x99", "0x99"}, // unknown code — returned verbatim
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			t.Parallel()
			if got := armImplementerName(tt.code); got != tt.want {
				t.Errorf("armImplementerName(%q) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

// TestArmPartName guards every recognized ARM-Ltd and Ampere part code plus
// the unknown-part (vendor-only, empty string) fallback and the
// unrecognized-implementer branch.
func TestArmPartName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		implementer string
		part        string
		want        string
	}{
		{"Cortex-A53", "0x41", "0xd03", "Cortex-A53"},
		{"Cortex-A55", "0x41", "0xd05", "Cortex-A55"},
		{"Cortex-A57", "0x41", "0xd07", "Cortex-A57"},
		{"Cortex-A72", "0x41", "0xd08", "Cortex-A72"},
		{"Cortex-A76", "0x41", "0xd0b", "Cortex-A76"},
		{"Neoverse-N1", "0x41", "0xd0c", "Neoverse-N1"},
		{"Neoverse-V1", "0x41", "0xd40", "Neoverse-V1"},
		{"Neoverse-N2", "0x41", "0xd49", "Neoverse-N2"},
		{"unknown ARM part", "0x41", "0xffff", ""},
		{"AmpereOne", "0xc0", "0xac3", "AmpereOne"},
		{"unknown Ampere part", "0xc0", "0xffff", ""},
		{"unrecognized implementer", "0x99", "0xd0c", ""},
		{"case-insensitive", "0X41", "0XD0C", "Neoverse-N1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := armPartName(tt.implementer, tt.part); got != tt.want {
				t.Errorf("armPartName(%q, %q) = %q, want %q", tt.implementer, tt.part, got, tt.want)
			}
		})
	}
}

// ARM bare-metal (e.g. Raspberry Pi) exposes a "Hardware" field used as the model.
func TestParseProcCPUInfo_armHardwareField(t *testing.T) {
	const data = `processor	: 0
processor	: 1
processor	: 2
processor	: 3
Hardware	: BCM2835
`
	got := parseProcCPUInfo(data)
	if got.threads != 4 {
		t.Errorf("threads = %d, want 4", got.threads)
	}
	if got.model != "BCM2835" {
		t.Errorf("model = %q, want BCM2835 (Hardware field)", got.model)
	}
}
