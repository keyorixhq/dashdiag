package canaryoracle

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// The oracle must see planted survivors in every encoding, and stay silent on a
// perfect redactor.
func TestPlantedSurvivorsDetected(t *testing.T) {
	can := New("plant", Secret, 7, true)
	for _, v := range can.Variants() {
		sc := NewScanner(can)
		hay := []byte("prefix " + string(v.Bytes) + " suffix")
		if len(sc.Scan("out", hay)) == 0 {
			t.Errorf("planted variant %s not detected", v.Name)
		}
	}
	leaky := func(s string) string { return strings.ReplaceAll(s, can.Raw, hex.EncodeToString([]byte(can.Raw))) }
	if len(NewScanner(can).Scan("o", []byte(leaky("pw="+can.Raw)))) == 0 {
		t.Error("hex-encoding redactor survivor not detected")
	}
	b64 := func(s string) string {
		return strings.ReplaceAll(s, can.Raw, base64.StdEncoding.EncodeToString([]byte(can.Raw)))
	}
	if len(NewScanner(can).Scan("o", []byte(b64("pw="+can.Raw)))) == 0 {
		t.Error("base64 survivor not detected")
	}
	perfect := strings.ReplaceAll("pw="+can.Raw, can.Raw, "[REDACTED]")
	if h := NewScanner(can).Scan("o", []byte(perfect)); len(h) != 0 {
		t.Errorf("control produced %d hits", len(h))
	}
}
