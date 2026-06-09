package runner

// availabler is the visibility contract a collector result opts into when it can
// be "not applicable" on a host. Result types with an `Available bool` field
// implement it in internal/models/availability.go (one method per type, enforced
// by a meta-test there).
type availabler interface{ IsAvailable() bool }

// IsAvailable reports whether a collector result is "present / applicable" on
// this host. It is the single source of truth shared by both surfaces that need
// the decision:
//   - live dsd health (render.shouldHideRow) hides not-applicable rows
//   - dsd health --report (baseline.BuildSnapshot) drops them from the snapshot
//
// Keeping one definition here is deliberate: the two surfaces previously each
// carried their own copy, drifted apart, and leaked phantom "X ✅ OK" rows into
// --report for collectors that the live view already hid (Battery/VLAN/Ceph/…).
//
// A result that implements availabler decides for itself; a type that does not
// (CPU, Memory's siblings without the field, NVMe, …) is always present. nil
// data is treated as absent.
func IsAvailable(data interface{}) bool {
	if data == nil {
		return false
	}
	if a, ok := data.(availabler); ok {
		return a.IsAvailable()
	}
	return true // no availability contract — always show
}
