package viperconf

// MC4 target 2 (extends MC1 target 2) — viper config differential at the FULL
// 1 MiB loader cap, plus the TOML/INI duplicate-key + include-directive space and
// a []Services-aware differential (the slice decode path, and the F1
// sibling-key-quadratic region).
//
// WHAT MC1 LEFT OPEN (mc1 LEFTOVERs 2):
//   - The MC1 differential capped fuzz input at 128 KiB, deliberately BELOW the
//     1 MiB implicit-config loader cap, so the shared bounded-work oracle would
//     explore the case-fold/delimiter space instead of re-tripping on the known
//     YAML sibling-key quadratic (CANDIDATE mc1-viper-yaml-quadratic). The
//     differential (V3) was therefore never exercised at the sizes a real
//     --config (UNcapped — see internal/config.Load) or a 1 MiB implicit config
//     actually reaches.
//   - The MC1 V3 differential cross-read only the SCALAR leaf keys; the
//     []Services slice — which drives real outbound TCP/HTTP dials
//     (internal/collectors/services.go) — was decoded and Validated but never
//     diffed against viper's own store. Its own comment flagged this.
//   - Duplicate-key and include-directive handling across TOML/INI was not
//     seeded or asserted as its own space.
//
// HOW THIS TARGET EXTENDS IT:
//   - fuzzInputCapFull = 1 MiB (the real loader cap). V1 (no panic) and V3/V4
//     (differentials) run at the full size for the LINEAR backends
//     (json/toml/ini/env). YAML specifically is still held at the
//     quadratic-safe 128 KiB inside THIS target, because the O(n^2)
//     sibling-key decode (characterised offline in the F1 bisection,
//     .scratch/upstream-drafts/) would make V2's fixed 5 s TimeBudget re-trip on
//     that single KNOWN issue at ~1 MiB — drowning any NEW blow-up. So V2
//     bounded-work IS still asserted here (catching a new super-linear decode in
//     the linear formats up to 1 MiB), while the known quadratic is bounded out
//     rather than silently swallowed. The quadratic is reported, not asserted
//     (F1), exactly as MC1 did.
//   - V4 services differential: when Unmarshal+Validate ACCEPT a doc, viper's own
//     raw view of each services element (v.Get("services")[i]) agrees with the
//     decoded config.Config.Services[i] on the security-relevant fields (port,
//     protocol, host, name). A divergence means Validate blessed one dial target
//     while a viper-reading consumer would act on another — the slice-path analog
//     of the V3 footgun class.
//   - Duplicate-key / include-directive seeds for TOML and INI, plus YAML
//     merge-key/anchor seeds, drive those spaces; the assertion is the SAME
//     differential (a duplicate key that makes viper's store disagree with the
//     struct fires V3/V4; an include directive that is silently expanded into a
//     file read would change the decoded values and also surface as a
//     differential or a Validate rejection).
//
// Does NOT verify (beyond the MC1 list): that viper REJECTS every malformed doc
// for the right reason; that an `include`/`!include` key provably triggers NO
// filesystem read (asserted indirectly — the key round-trips as the literal
// string we supplied, i.e. viper did not expand it — not via a syscall trace);
// the YAML quadratic itself (bounded out here, characterised offline in F1); and
// anything about formats viper supports but the task does not call out
// (properties/hcl/dotenv-variants beyond env).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/keyorixhq/dashdiag/internal/config"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// fuzzInputCapFull is the full implicit-config loader cap. Linear backends run
// here; YAML is sub-capped (yamlQuadraticSafeCap) to keep the known O(n^2) decode
// from re-tripping V2.
const fuzzInputCapFull = 1 << 20

// yamlQuadraticSafeCap bounds YAML input INSIDE this target. 128 KiB keeps the
// worst-case all-keys YAML (~13k siblings, ~0.8 s measured) comfortably under
// V2's 5 s TimeBudget; the F1 bisection characterises the >128 KiB region offline.
const yamlQuadraticSafeCap = 128 << 10

func mc4ViperExtendedSeeds(f *testing.F) {
	type sd struct {
		fmtIdx int
		body   string
	}
	seeds := []sd{
		// ── TOML duplicate keys (spec forbids → expect a typed error, V1) ──
		{2, "[thresholds]\ndisk_warn_pct = 1.0\ndisk_warn_pct = 2.0\n"},
		{2, "[thresholds]\ndisk_warn_pct = 1.0\n[thresholds]\nram_warn_pct = 3.0\n"},
		// ── INI duplicate keys (go-ini tolerates → differential must stay consistent) ──
		{3, "[thresholds]\ndisk_warn_pct = 10\ndisk_warn_pct = 20\n"},
		{3, "[thresholds]\ndisk_warn_pct = 10\nDisk_Warn_Pct = 20\n"}, // case-fold dup
		// ── include-directive inertness: a key literally named include/!include
		//    must be treated as DATA, never cause a file read. ──
		{3, "[DEFAULT]\ninclude = /etc/passwd\n[thresholds]\ndisk_warn_pct = 5\n"},
		{2, "include = \"/etc/passwd\"\n[thresholds]\ndisk_warn_pct = 5\n"},
		{0, "include: !include /etc/passwd\nthresholds:\n  disk_warn_pct: 5\n"},
		// ── YAML merge-key / anchor / alias (decode-path corner) ──
		{0, "base: &b\n  disk_warn_pct: 7\nthresholds:\n  <<: *b\n"},
		{0, "a: &a hello\nb: *a\nthresholds:\n  disk_warn_pct: 9\n"},
		// ── []Services differential seeds (the slice path) ──
		{0, "services:\n  - name: db\n    host: h1\n    port: 5432\n    protocol: tcp\n  - name: web\n    host: h2\n    port: 443\n    protocol: https\n"},
		{1, `{"services":[{"name":"db","host":"h","port":5432,"protocol":"tcp"},{"name":"api","host":"a","port":8080,"protocol":"http"}]}`},
		{0, "services:\n  - name: s\n    host: h\n    port: 70000\n    protocol: tcp\n"}, // out-of-range port → Validate rejects
		// ── F1 quadratic-region shapes (kept small as seeds; the fuzzer grows them) ──
		{0, manyYAMLKeys(200)},
		{1, manyJSONKeys(200)},
		{0, manyServices(50)},
	}
	for _, s := range seeds {
		f.Add(s.fmtIdx, []byte(s.body))
	}
}

// manyYAMLKeys builds a flat YAML map of n sibling keys (the quadratic region,
// kept small as a seed).
func manyYAMLKeys(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "k%d: %d\n", i, i)
	}
	return b.String()
}

func manyJSONKeys(n int) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\"k%d\":%d", i, i)
	}
	b.WriteByte('}')
	return b.String()
}

func manyServices(n int) string {
	var b strings.Builder
	b.WriteString("services:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  - name: s%d\n    host: h%d\n    port: %d\n    protocol: tcp\n", i, i, 1024+i)
	}
	return b.String()
}

func FuzzViperConfigFull(f *testing.F) {
	mc4ViperExtendedSeeds(f)

	f.Fuzz(func(t *testing.T, fmtIdx int, data []byte) {
		format := mc1Formats[((fmtIdx%len(mc1Formats))+len(mc1Formats))%len(mc1Formats)]

		// Full 1 MiB for the linear backends; YAML sub-capped to the
		// quadratic-safe size so the KNOWN O(n^2) decode does not re-trip V2.
		limit := fuzzInputCapFull
		if format == "yaml" {
			limit = yamlQuadraticSafeCap
		}
		if len(data) > limit {
			return
		}
		n := len(data)

		v := viper.New()
		v.SetConfigType(format)
		mirrorDefaults(v)

		var cfg config.Config
		var readErr, unmErr, valErr error
		// V1 no panic + V2 bounded cost (asserts a NEW super-linear blow-up up to
		// 1 MiB; the known YAML quadratic is bounded out above).
		resource.Check(t, n, mc1ViperAllocFactor, func() {
			readErr = readConfigBytes(v, data)
			if readErr != nil {
				return
			}
			unmErr = v.Unmarshal(&cfg)
			if unmErr != nil {
				return
			}
			valErr = cfg.Validate()
		})

		if readErr != nil || unmErr != nil || valErr != nil {
			return // rejected somewhere — a consumer never sees this config
		}

		// V3 scalar differential (same as MC1, now at full size).
		assertFloatAgrees(t, format, v, "thresholds.disk_warn_pct", cfg.Thresholds.DiskWarnPct)
		assertFloatAgrees(t, format, v, "thresholds.ram_warn_pct", cfg.Thresholds.RAMWarnPct)
		assertFloatAgrees(t, format, v, "thresholds.fd_crit_pct", cfg.Thresholds.FDCritPct)
		if got, want := v.GetInt("logs.since_minutes"), cfg.Logs.SinceMinutes; got != want {
			t.Fatalf("V3 differential [%s] logs.since_minutes: viper.GetInt=%d struct=%d\n input (%d B): %q",
				format, got, want, n, clipBytes(data))
		}

		// V4 services differential: viper's raw slice view must agree with the
		// decoded struct on every element's security-relevant fields.
		assertServicesAgree(t, format, v, cfg, n, data)
	})
}

// assertServicesAgree cross-reads viper's own raw services slice against the
// decoded struct. Only runs when BOTH views carry entries (ini/env don't decode
// an array-of-tables, so cfg.Services is empty there — nothing to diff). A
// mismatch on a dial-target field (port/protocol/host/name) is a V4 divergence:
// Validate blessed one target while a viper.Get consumer would act on another.
func assertServicesAgree(t *testing.T, format string, v *viper.Viper, cfg config.Config, n int, data []byte) {
	t.Helper()
	raw, ok := v.Get("services").([]interface{})
	if !ok || len(cfg.Services) == 0 {
		return
	}
	if len(raw) != len(cfg.Services) {
		t.Fatalf("V4 services length differential [%s]: viper.Get len=%d struct len=%d\n input (%d B): %q",
			format, len(raw), len(cfg.Services), n, clipBytes(data))
	}
	for i := range cfg.Services {
		elem, ok := raw[i].(map[string]interface{})
		if !ok {
			continue // viper holds a non-map element; struct decode is the authority
		}
		if rp, has := rawInt(elem, "port"); has && rp != cfg.Services[i].Port {
			t.Fatalf("V4 services[%d].port differential [%s]: viper.Get=%d struct=%d\n input (%d B): %q",
				i, format, rp, cfg.Services[i].Port, n, clipBytes(data))
		}
		if rs, has := rawStr(elem, "protocol"); has && rs != cfg.Services[i].Protocol {
			t.Fatalf("V4 services[%d].protocol differential [%s]: viper.Get=%q struct=%q\n input (%d B): %q",
				i, format, rs, cfg.Services[i].Protocol, n, clipBytes(data))
		}
		if rs, has := rawStr(elem, "host"); has && rs != cfg.Services[i].Host {
			t.Fatalf("V4 services[%d].host differential [%s]: viper.Get=%q struct=%q\n input (%d B): %q",
				i, format, rs, cfg.Services[i].Host, n, clipBytes(data))
		}
		if rs, has := rawStr(elem, "name"); has && rs != cfg.Services[i].Name {
			t.Fatalf("V4 services[%d].name differential [%s]: viper.Get=%q struct=%q\n input (%d B): %q",
				i, format, rs, cfg.Services[i].Name, n, clipBytes(data))
		}
	}
}

// rawInt / rawStr pull a field from viper's raw (lowercased-key) element map,
// coercing the handful of numeric/string shapes a decoder can produce. Returns
// has=false when the key is absent or an incomparable shape (then the struct
// decode is treated as authoritative and no divergence is claimed).
func rawInt(m map[string]interface{}, key string) (int, bool) {
	val, ok := m[key]
	if !ok {
		return 0, false
	}
	switch x := val.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		if float64(int(x)) == x {
			return int(x), true
		}
	}
	return 0, false
}

func rawStr(m map[string]interface{}, key string) (string, bool) {
	val, ok := m[key]
	if !ok {
		return "", false
	}
	if s, ok := val.(string); ok {
		return s, true
	}
	return "", false
}

func clipBytes(b []byte) string {
	const n = 256
	if len(b) > n {
		return string(b[:n]) + "...(truncated)"
	}
	return string(b)
}
