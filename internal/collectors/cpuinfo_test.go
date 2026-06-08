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

// ARM /proc/cpuinfo has "processor" lines but no "model name"; the model falls
// back to the implementer code.
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
	if got.model != "ARM ARM (aarch64)" {
		t.Errorf("model = %q, want ARM implementer fallback", got.model)
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
