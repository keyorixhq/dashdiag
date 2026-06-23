package analysis

// Shared temperature-plausibility logic. The same "is this a real reading or a
// sentinel/garbage value?" question is asked by every collector that surfaces a
// temperature — GPU thermals, NVMe/SATA SMART, and the `dsd hardware` sensor
// display. It was independently re-implemented at each site (TRIAGE: GPU #436,
// NVMe SMART #440, hardware display #441), and the 0-Kelvin sentinel bug
// re-appeared on each new surface. Consolidating it here means a new surface
// gets the correct behaviour for free.
//
// CONVENTION: any new code that scores or displays a temperature MUST route
// through TempPlausible / TempNotReported — do NOT re-inline a
// `c < -40 || c > N` check or a `c <= -273` sentinel test.

// Plausible-temperature bounds (°C). The floor is shared across device classes:
// below -40°C no operating component reads, and the 0-Kelvin (-273°C) "not
// reported" sentinel falls there too. Ceilings differ by class — silicon
// (GPU/CPU/board) survives higher than a drive's rated range.
const (
	tempFloorC = -40.0

	// TempCeilNVMe bounds NVMe/SATA drive temperatures (operating + storage max).
	TempCeilNVMe = 125.0
	// TempCeilSilicon bounds GPU/CPU/board silicon sensors — they throttle then
	// hard-shut-down well below this; anything above is garbage, not an overheat.
	TempCeilSilicon = 150.0
)

// TempPlausible reports whether a temperature (°C) is a real, in-range reading
// for a device with the given ceiling. A value below -40°C (including the
// 0-Kelvin "not reported" sentinel) or above the ceiling is not a real
// measurement and must not be scored as a verdict or rendered as healthy.
func TempPlausible(c, ceilingC float64) bool {
	return c >= tempFloorC && c <= ceilingC
}

// TempNotReported reports the 0-Kelvin (-273°C / 0 K) "no sensor" sentinel that
// virtual/cloud devices (AWS EBS and other hypervisor-presented hardware) return
// when they expose no thermal sensor. Distinct from a device actively reporting
// an impossible value (e.g. VMware's 11758°C) — that's garbage to reject, this
// is "not measured" to surface as unverified.
func TempNotReported(c float64) bool {
	return c <= -273
}
