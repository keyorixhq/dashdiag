package runner

import "reflect"

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
// The contract: a collector that is not applicable on the current platform
// signals it by either implementing IsAvailable() bool, or exposing a bool
// `Available` field set to false. Anything without that field is always
// considered present (e.g. CPU, Memory, NVMe — they have no Available field).
func IsAvailable(data interface{}) bool {
	if data == nil {
		return false
	}
	if a, ok := data.(interface{ IsAvailable() bool }); ok {
		return a.IsAvailable()
	}
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return true // unknown type — show by default
	}
	f := v.FieldByName("Available")
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return true // no Available field — always show
	}
	return f.Bool()
}
