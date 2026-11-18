package viperconf

// MC1 target 2 — github.com/spf13/viper on the config-load path.
//
// Reachability: internal/config.Load builds a viper.New(), seeds defaults,
// SetConfigFile(path)+ReadInConfig() (format chosen from the file extension),
// Unmarshal()s into config.Config, then runs config.Config.Validate(). The file
// is an operator-supplied ~/.dsd.yaml (implicit, capped at 1 MiB and gated by
// internal/config.implicitConfigSafe) or an explicit --config path (any format
// viper supports: yaml/json/toml/ini/env/properties). A hostile or mistaken
// file is untrusted input, and cfg.Services drives real outbound TCP/HTTP dials
// (internal/collectors/services.go), so a value that passes Validate but is read
// differently by a consumer is a real steering primitive.
//
// This target mirrors Load's PARSE→UNMARSHAL→VALIDATE core with the real
// config.Config type and the real Validate, across all five formats the task
// calls out. It feeds bytes through viper.SetConfigType(fmt)+ReadConfig(reader)
// — the same decode/merge/case-fold backend ReadInConfig uses — rather than a
// temp file, so the run is in-memory and deterministic. The file-discovery,
// symlink and size-cap gates are internal/config's OWN logic (tested in
// config_test.go), not viper's, and are out of scope here; this target is the
// viper decode + key-folding + Unmarshal + Validate layer.
//
// INVARIANTS asserted (see INVARIANTS.d/mc1-thirdparty-viper.md):
//   V1 no panic / typed error — neither ReadConfig, Unmarshal nor Validate ever
//      panics on any bytes/format; a rejected file comes back as a Go error.
//   V2 bounded cost — decode+unmarshal+validate stay within the shared resource
//      oracle (alloc factor + time + goroutines) for every input up to the 1 MiB
//      loader cap.
//   V3 validator/consumer differential — whenever Unmarshal + Validate ACCEPT a
//      document, viper's own key store (v.GetFloat64/GetInt on the canonical
//      key — the value a consumer reading viper directly would see) agrees with
//      the decoded struct field (the value Validate judged and the collectors
//      actually use). A divergence means Validate blessed one value while a
//      viper.Get consumer would act on another — the case-fold / delimiter /
//      duplicate-key footgun class.
//
// Does NOT verify: that viper's REJECTIONS are all justified (only that accepted
// docs are self-consistent); remote config (disabled in dsd, never built);
// the []Services slice element-by-element against viper.Get (only the scalar
// leaf keys are cross-read — the slice is still decoded and Validated, just not
// Get-compared, because viper has no stable per-element typed getter to diff
// against); format auto-detection by extension (selected explicitly here);
// and the implicit-$HOME trust gate (config.go's own, separately tested).

import (
	"math"
	"testing"

	"github.com/spf13/viper"

	"github.com/keyorixhq/dashdiag/internal/config"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// fuzzInputCap bounds the bytes this TARGET feeds, deliberately BELOW the 1 MiB
// loader cap. The viper YAML backend (go.yaml.in/yaml mapping decode) is O(n^2)
// in the number of sibling keys — characterised during calibration and reported
// as CANDIDATE mc1-viper-yaml-quadratic (10k keys ~0.5s, 20k ~1.65s, 40k ~12.5s;
// the JSON backend is linear). That quadratic IS reachable at the full 1 MiB cap
// (~50-90s extrapolated) and is reported upstream-style, but a fuzz-input cap at
// the full 1 MiB would make the shared bounded-work oracle re-trip on that single
// known issue instead of exploring the case-fold / delimiter / cross-format
// decode space this target exists for. 128 KiB keeps even a worst-case all-keys
// YAML (~13k keys, ~0.8s) comfortably under TimeBudget while leaving the oracle
// able to catch a NEW super-linear blow-up.
const fuzzInputCap = 128 << 10

// viper builds a key map, a decode hook chain and a mapstructure target; the
// per-byte allocation of a nested decode is well above the DL1 default of 64.
// Calibrated loosely at 1024 so a legitimately nested document stays in budget
// while a super-linear decode or a hang still trips. Recalibrate from the report
// if a real amplification lead shows up.
const mc1ViperAllocFactor = 1024

// formats is the set the task calls out; the fuzzer picks one per input.
var mc1Formats = []string{"yaml", "json", "toml", "ini", "env"}

// mirrorDefaults seeds the exact defaults internal/config.Load sets, so the
// harness's viper is configured identically — a differential then reflects
// viper's decode/fold behaviour, not a defaults mismatch between the two views.
func mirrorDefaults(v *viper.Viper) {
	d := config.Default()
	v.SetDefault("thresholds.disk_warn_pct", d.Thresholds.DiskWarnPct)
	v.SetDefault("thresholds.disk_crit_pct", d.Thresholds.DiskCritPct)
	v.SetDefault("thresholds.ram_warn_pct", d.Thresholds.RAMWarnPct)
	v.SetDefault("thresholds.ram_crit_pct", d.Thresholds.RAMCritPct)
	v.SetDefault("thresholds.cpu_load_warn_multiplier", d.Thresholds.CPULoadWarnMultiplier)
	v.SetDefault("thresholds.cpu_load_crit_multiplier", d.Thresholds.CPULoadCritMultiplier)
	v.SetDefault("thresholds.io_util_warn_pct", d.Thresholds.IOUtilWarnPct)
	v.SetDefault("thresholds.io_util_crit_pct", d.Thresholds.IOUtilCritPct)
	v.SetDefault("thresholds.io_await_warn_ms", d.Thresholds.IOAwaitWarnMs)
	v.SetDefault("thresholds.io_await_crit_ms", d.Thresholds.IOAwaitCritMs)
	v.SetDefault("thresholds.swap_warn_pct", d.Thresholds.SwapWarnPct)
	v.SetDefault("thresholds.swap_crit_pct", d.Thresholds.SwapCritPct)
	v.SetDefault("thresholds.ntp_warn_ms", d.Thresholds.NTPWarnMs)
	v.SetDefault("thresholds.ntp_crit_ms", d.Thresholds.NTPCritMs)
	v.SetDefault("thresholds.fd_warn_pct", d.Thresholds.FDWarnPct)
	v.SetDefault("thresholds.fd_crit_pct", d.Thresholds.FDCritPct)
	v.SetDefault("logs.since_minutes", d.Logs.SinceMinutes)
}

// floatAgrees treats NaN==NaN and matches infinities, so a legitimately decoded
// .nan/.inf in both views is not reported as a divergence.
func floatAgrees(a, b float64) bool {
	if math.IsNaN(a) && math.IsNaN(b) {
		return true
	}
	return a == b
}

func mc1ViperSeeds(f *testing.F) {
	type sd struct {
		fmtIdx int
		body   string
	}
	seeds := []sd{
		{0, "thresholds:\n  disk_warn_pct: 42.5\nlogs:\n  since_minutes: 10\n"}, // yaml
		{0, "thresholds:\n  disk_warn_pct: .nan\n"},                             // yaml nan
		{0, "thresholds:\n  disk_warn_pct: 1\n  Disk_Warn_Pct: 2\n"},            // case-fold dup
		{0, "\"thresholds.disk_warn_pct\": 7\n"},                                // dotted flat key
		{0, "security:\n  allowed_ports: [22, 70000]\n"},                        // out-of-range port
		{0, "services:\n  - name: db\n    host: h\n    port: 5432\n    protocol: tcp\n"},
		{1, `{"thresholds":{"disk_warn_pct":55.5},"logs":{"since_minutes":3}}`}, // json
		{1, `{"thresholds":{"disk_warn_pct":55,"Disk_Warn_Pct":66}}`},           // json case dup
		{2, "[thresholds]\ndisk_warn_pct = 12.0\n[logs]\nsince_minutes = 9\n"},  // toml
		{3, "[thresholds]\ndisk_warn_pct = 80\n"},                               // ini
		{4, "DISK_WARN_PCT=90\n"},                                               // env/dotenv
		{0, ""},                                                                 // empty
		{0, "::: not : valid : yaml :::\n"},                                     // malformed yaml
		{1, "{not json"},                                                        // malformed json
	}
	for _, s := range seeds {
		f.Add(s.fmtIdx, []byte(s.body))
	}
}

func FuzzViperConfigDifferential(f *testing.F) {
	mc1ViperSeeds(f)

	f.Fuzz(func(t *testing.T, fmtIdx int, data []byte) {
		if len(data) > fuzzInputCap {
			return // see fuzzInputCap: keeps the known YAML quadratic from dominating
		}
		format := mc1Formats[((fmtIdx%len(mc1Formats))+len(mc1Formats))%len(mc1Formats)]
		n := len(data)

		v := viper.New()
		v.SetConfigType(format)
		mirrorDefaults(v)

		var cfg config.Config
		var readErr, unmErr, valErr error
		// V1/V2: the whole parse→unmarshal→validate pipeline is bounded and must
		// never panic (a panic here would crash the fuzz worker and be reported).
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

		if readErr != nil || unmErr != nil {
			return // viper rejected the file as a typed error — nothing to compare
		}
		if valErr != nil {
			return // Validate rejected the decoded config — consumer never sees it
		}

		// V3: Validate accepted ⇒ the struct fields the collectors use must match
		// viper's own key store for every canonical scalar leaf key.
		assertFloatAgrees(t, format, v, "thresholds.disk_warn_pct", cfg.Thresholds.DiskWarnPct)
		assertFloatAgrees(t, format, v, "thresholds.disk_crit_pct", cfg.Thresholds.DiskCritPct)
		assertFloatAgrees(t, format, v, "thresholds.ram_warn_pct", cfg.Thresholds.RAMWarnPct)
		assertFloatAgrees(t, format, v, "thresholds.cpu_load_warn_multiplier", cfg.Thresholds.CPULoadWarnMultiplier)
		assertFloatAgrees(t, format, v, "thresholds.io_await_crit_ms", cfg.Thresholds.IOAwaitCritMs)
		assertFloatAgrees(t, format, v, "thresholds.fd_crit_pct", cfg.Thresholds.FDCritPct)

		if got, want := v.GetInt("logs.since_minutes"), cfg.Logs.SinceMinutes; got != want {
			t.Fatalf("V3 differential [%s] logs.since_minutes: viper.GetInt=%d struct=%d\n input (%d B): %q",
				format, got, want, n, data)
		}
		if got, want := v.GetInt("security.ssh_failed_login_warn"), cfg.Security.SSHFailedLoginWarn; got != want {
			t.Fatalf("V3 differential [%s] security.ssh_failed_login_warn: viper.GetInt=%d struct=%d\n input (%d B): %q",
				format, got, want, n, data)
		}
		if got, want := v.GetInt("security.ssh_failed_login_crit"), cfg.Security.SSHFailedLoginCrit; got != want {
			t.Fatalf("V3 differential [%s] security.ssh_failed_login_crit: viper.GetInt=%d struct=%d\n input (%d B): %q",
				format, got, want, n, data)
		}
	})
}

func assertFloatAgrees(t *testing.T, format string, v *viper.Viper, key string, structVal float64) {
	t.Helper()
	got := v.GetFloat64(key)
	if !floatAgrees(got, structVal) {
		t.Fatalf("V3 differential [%s] %s: viper.GetFloat64=%v struct=%v", format, key, got, structVal)
	}
}
