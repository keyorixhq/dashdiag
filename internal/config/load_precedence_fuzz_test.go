package config

// load_precedence_fuzz_test.go — FuzzLoadPrecedenceMetamorphic drives the
// live config path, Load("") (the implicit $HOME/.dsd.yaml lookup that
// internal/collectors/services.go performs on every health run), through
// viper + yaml.v3 + mapstructure, with $HOME pointed at a fresh temp dir.
//
// Who controls the bytes: whoever can write $HOME/.dsd.yaml — normally the
// operator; under `sudo -E` a preserved unprivileged $HOME (gated by the
// root-owner check, which this harness does not reach as non-root).
//
// Oracles:
//  1. Precedence model: a key the file sets wins; a threshold/logs key it
//     does not set keeps its default; Services is exactly the file's list.
//     The expected Config is built independently (defaults struct + overlay),
//     never by reading viper back.
//  2. Rendering metamorphic: the same logical config rendered as block YAML,
//     block YAML with every mapping's key order reversed, and flow (JSON-
//     shaped) YAML must Load to identical results (config and error/no
//     error).
//  3. Environment independence: DSD_*/THRESHOLDS_* style environment
//     variables must not change the result (dsd's viper has no env binding;
//     a future AutomaticEnv would be a silent precedence change).
//  4. Unsafe-file gate: a group/world-writable implicit config is ignored
//     entirely — defaults, nil error — whatever it contains.
//  5. No secret echo: a sentinel placed in an unknown key and appended to a
//     third of the service hosts never appears in Load's error text (that error is
//     surfaced into health output and the MCP dsd_health response).
//
// What this does NOT verify: the Security section's defaults when the file
// omits it (reported as NET1-F4 with its own reproducer; oracle 1 only
// compares Security when the file sets it completely); unknown keys that
// case-fold (strings.EqualFold, which mapstructure uses) or dot-split
// (viper's key delimiter) onto a known key — that aliasing is viper's
// documented behaviour, so such keys are excluded by the generator; type-
// mismatched scalars (a string where a number is expected — weak decoding);
// the root-owner gate and the symlink refusal (need root / are unit-tested
// in config_test.go); the explicit-path branch (no live caller passes one).

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const cfgSecretSentinel = "S3NT1NEL-hunter2-do-not-echo"

var thresholdKeys = []string{
	"disk_warn_pct", "disk_crit_pct", "ram_warn_pct", "ram_crit_pct",
	"cpu_load_warn_multiplier", "cpu_load_crit_multiplier",
	"io_util_warn_pct", "io_util_crit_pct", "io_await_warn_ms", "io_await_crit_ms",
	"swap_warn_pct", "swap_crit_pct", "ntp_warn_ms", "ntp_crit_ms",
	"fd_warn_pct", "fd_crit_pct",
}

// thresholdPtr maps a yaml key to the field of t, independently of viper.
func thresholdPtr(t *ThresholdConfig, key string) *float64 {
	m := map[string]*float64{
		"disk_warn_pct": &t.DiskWarnPct, "disk_crit_pct": &t.DiskCritPct,
		"ram_warn_pct": &t.RAMWarnPct, "ram_crit_pct": &t.RAMCritPct,
		"cpu_load_warn_multiplier": &t.CPULoadWarnMultiplier, "cpu_load_crit_multiplier": &t.CPULoadCritMultiplier,
		"io_util_warn_pct": &t.IOUtilWarnPct, "io_util_crit_pct": &t.IOUtilCritPct,
		"io_await_warn_ms": &t.IOAwaitWarnMs, "io_await_crit_ms": &t.IOAwaitCritMs,
		"swap_warn_pct": &t.SwapWarnPct, "swap_crit_pct": &t.SwapCritPct,
		"ntp_warn_ms": &t.NTPWarnMs, "ntp_crit_ms": &t.NTPCritMs,
		"fd_warn_pct": &t.FDWarnPct, "fd_crit_pct": &t.FDCritPct,
	}
	return m[key]
}

// yNode is a tiny ordered YAML document model the generator renders three ways.
type yNode struct {
	scalar string // pre-rendered scalar, when kids == nil && list == nil
	keys   []string
	kids   []*yNode
	list   []*yNode
	isList bool
}

func yScalar(s string) *yNode { return &yNode{scalar: s} }

func (n *yNode) set(k string, v *yNode) { n.keys = append(n.keys, k); n.kids = append(n.kids, v) }

func yFloat(v float64) string {
	switch {
	case math.IsNaN(v):
		return ".nan"
	case math.IsInf(v, 1):
		return ".inf"
	case math.IsInf(v, -1):
		return "-.inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// yString renders s (valid UTF-8) as a YAML double-quoted scalar, escaping
// every rune outside YAML's c-printable set (json.Marshal is not enough: it
// leaves DEL and C1 controls raw, which YAML forbids in the stream).
func yString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case r == 0x20 || (r > 0x20 && r < 0x7f) ||
			(r >= 0xa0 && r <= 0xd7ff) || (r >= 0xe000 && r <= 0xfffd && r != 0xfeff) || r >= 0x10000:
			sb.WriteRune(r)
		default:
			fmt.Fprintf(&sb, `\u%04x`, r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func renderBlock(n *yNode, indent string, reverse bool, sb *strings.Builder) {
	if n.isList {
		for _, it := range n.list {
			if it.keys == nil && !it.isList {
				sb.WriteString(indent + "- " + it.scalar + "\n")
				continue
			}
			sb.WriteString(indent + "-\n")
			renderBlock(it, indent+"  ", reverse, sb)
		}
		return
	}
	idx := make([]int, len(n.keys))
	for i := range idx {
		idx[i] = i
	}
	if reverse {
		slices.Reverse(idx)
	}
	for _, i := range idx {
		k, v := n.keys[i], n.kids[i]
		if v.isList && len(v.list) == 0 {
			sb.WriteString(indent + yString(k) + ": []\n")
			continue
		}
		if v.keys == nil && !v.isList {
			sb.WriteString(indent + yString(k) + ": " + v.scalar + "\n")
			continue
		}
		sb.WriteString(indent + yString(k) + ":\n")
		renderBlock(v, indent+"  ", reverse, sb)
	}
}

func renderFlow(n *yNode) string {
	if n.isList {
		parts := make([]string, len(n.list))
		for i, it := range n.list {
			parts[i] = renderFlow(it)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	if n.keys == nil {
		if n.kids == nil && n.scalar != "" {
			return n.scalar
		}
		return "{}"
	}
	parts := make([]string, len(n.keys))
	for i, k := range n.keys {
		parts[i] = yString(k) + ": " + renderFlow(n.kids[i])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// fuzzBytes is a tiny cursor over the fuzz input.
type fuzzBytes struct{ b []byte }

func (f *fuzzBytes) u8() byte {
	if len(f.b) == 0 {
		return 0
	}
	v := f.b[0]
	f.b = f.b[1:]
	return v
}

func (f *fuzzBytes) u64() uint64 {
	var buf [8]byte
	n := copy(buf[:], f.b)
	f.b = f.b[n:]
	return binary.BigEndian.Uint64(buf[:])
}

func (f *fuzzBytes) str(max int) string {
	l := min(int(f.u8())%(max+1), len(f.b))
	s := strings.ToValidUTF8(string(f.b[:l]), "?")
	f.b = f.b[l:]
	return s
}

// knownAlias reports whether an extra top-level key could alias a known key
// through viper's dot delimiter or mapstructure's EqualFold matching.
func knownAlias(k string) bool {
	known := make([]string, 0, 4+len(thresholdKeys)+8)
	known = append(known, "thresholds", "logs", "security", "services")
	known = append(known, thresholdKeys...)
	known = append(known, "since_minutes", "allowed_ports", "ssh_failed_login_warn", "ssh_failed_login_crit", "name", "host", "port", "protocol")
	for seg := range strings.SplitSeq(k, ".") {
		for _, kn := range known {
			if strings.EqualFold(seg, kn) {
				return true
			}
		}
	}
	return false
}

type genConfig struct {
	doc         *yNode
	want        Config
	securitySet bool
	hosts       []string
	unsafePerm  bool
}

func generate(data []byte) genConfig {
	fb := &fuzzBytes{b: data}
	g := genConfig{want: defaults}
	g.want.Security.AllowedPorts = slices.Clone(defaults.Security.AllowedPorts)
	g.doc = &yNode{}

	mask := fb.u64()
	th := &yNode{}
	for i, k := range thresholdKeys {
		if mask>>i&1 == 0 {
			continue
		}
		var v float64
		switch fb.u8() % 4 {
		case 0:
			v = math.Float64frombits(fb.u64()) // any bits incl. NaN/Inf/negative
		default:
			v = float64(fb.u8()) + float64(fb.u8())/256
		}
		th.set(k, yScalar(yFloat(v)))
		*thresholdPtr(&g.want.Thresholds, k) = v
	}
	if th.keys != nil {
		g.doc.set("thresholds", th)
	}
	if mask>>20&1 == 1 {
		m := int(int16(binary.BigEndian.Uint16([]byte{fb.u8(), fb.u8()})))
		g.doc.set("logs", &yNode{keys: []string{"since_minutes"}, kids: []*yNode{yScalar(strconv.Itoa(m))}})
		g.want.Logs.SinceMinutes = m
	}
	if mask>>21&1 == 1 {
		g.securitySet = true
		sec := &yNode{}
		ports := &yNode{isList: true}
		np := int(fb.u8() % 4)
		g.want.Security.AllowedPorts = []int{}
		for range np {
			p := int(int32(uint32(fb.u64())))
			if fb.u8()%2 == 0 {
				p = int(fb.u8()) + 1
			}
			ports.list = append(ports.list, yScalar(strconv.Itoa(p)))
			g.want.Security.AllowedPorts = append(g.want.Security.AllowedPorts, p)
		}
		w, c := int(int8(fb.u8())), int(fb.u8())
		sec.set("allowed_ports", ports)
		sec.set("ssh_failed_login_warn", yScalar(strconv.Itoa(w)))
		sec.set("ssh_failed_login_crit", yScalar(strconv.Itoa(c)))
		g.want.Security.SSHFailedLoginWarn, g.want.Security.SSHFailedLoginCrit = w, c
		g.doc.set("security", sec)
	}
	if ns := int(mask >> 22 & 3); ns > 0 && ns < 3 {
		svcs := &yNode{isList: true}
		for range ns {
			name, host := fb.str(12), fb.str(16)
			proto := []string{"tcp", "http", "https", "udp", ""}[fb.u8()%5]
			port := int(int32(uint32(fb.u64())))
			if fb.u8()%2 == 0 {
				port = int(binary.BigEndian.Uint16([]byte{fb.u8(), fb.u8()}))
			}
			if fb.u8()%3 == 0 {
				host += "@" + cfgSecretSentinel
			}
			g.hosts = append(g.hosts, host)
			s := &yNode{}
			s.set("name", yScalar(yString(name)))
			s.set("host", yScalar(yString(host)))
			s.set("port", yScalar(strconv.Itoa(port)))
			s.set("protocol", yScalar(yString(proto)))
			svcs.list = append(svcs.list, s)
			g.want.Services = append(g.want.Services, ServiceConfig{Name: name, Host: host, Port: port, Protocol: proto})
		}
		g.doc.set("services", svcs)
	}
	if mask>>24&1 == 1 {
		if k := fb.str(16); k != "" && !knownAlias(k) && utf8.ValidString(k) {
			g.doc.set(k, yScalar(yString(cfgSecretSentinel)))
		}
	}
	g.unsafePerm = mask>>25&7 == 7
	return g
}

type loadResult struct {
	cfg *Config
	err error
}

func loadWith(t *testing.T, home, content string, perm os.FileMode) loadResult {
	t.Helper()
	path := filepath.Join(home, ".dsd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load("")
	return loadResult{cfg: cfg, err: err}
}

func sameResult(a, b loadResult) bool {
	if (a.err == nil) != (b.err == nil) {
		return false
	}
	return reflect.DeepEqual(a.cfg, b.cfg)
}

func FuzzLoadPrecedenceMetamorphic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 1, 1, 80, 0})                     // one threshold
	f.Add([]byte{0, 0, 0, 0, 0, 0x30, 0, 1})                            // logs + security
	f.Add([]byte{0, 0, 0, 0, 0, 0x40, 0, 0, 3, 'w', 'e', 'b', 4, 'h'})  // one service
	f.Add([]byte{0, 0, 0, 0, 0, 0x80, 0, 0, 2, 'a', 'b', 2, 'h', 'h'})  // two services
	f.Add([]byte{0, 0, 0, 0, 1, 0, 0, 0, 5, 't', 'o', 'k', 'e', 'n'})   // unknown key
	f.Add([]byte{0, 0, 0, 0, 0x0e, 0, 0, 1, 0, 0x7f, 0xf8, 0, 0, 0, 0}) // NaN, unsafe perm
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0xbf, 0xf0, 0, 0, 0, 0, 0}) // negative

	envKeys := []string{"DSD_THRESHOLDS_DISK_WARN_PCT", "THRESHOLDS_DISK_WARN_PCT", "THRESHOLDS.DISK_WARN_PCT", "DSD_LOGS_SINCE_MINUTES", "LOGS_SINCE_MINUTES"}

	f.Fuzz(func(t *testing.T, data []byte) {
		g := generate(data)
		home := t.TempDir()
		prevHome, hadHome := os.LookupEnv("HOME")
		_ = os.Setenv("HOME", home)
		defer func() {
			if hadHome {
				_ = os.Setenv("HOME", prevHome)
			} else {
				_ = os.Unsetenv("HOME")
			}
		}()

		var block, rev strings.Builder
		renderBlock(g.doc, "", false, &block)
		renderBlock(g.doc, "", true, &rev)
		flow := renderFlow(g.doc) + "\n"
		perm := os.FileMode(0o600)
		if g.unsafePerm {
			perm = 0o620
		}

		base := loadWith(t, home, block.String(), perm)
		for name, content := range map[string]string{"reversed": rev.String(), "flow": flow} {
			if r := loadWith(t, home, content, perm); !sameResult(base, r) {
				t.Fatalf("rendering metamorphic: block vs %s differ\nblock:\n%s\n%s:\n%s\nblock -> %+v / %v\n%s -> %+v / %v",
					name, block.String(), name, content, base.cfg, base.err, name, r.cfg, r.err)
			}
		}

		for _, k := range envKeys {
			_ = os.Setenv(k, "12345")
		}
		envRes := loadWith(t, home, block.String(), perm)
		for _, k := range envKeys {
			_ = os.Unsetenv(k)
		}
		if !sameResult(base, envRes) {
			t.Fatalf("environment independence: env vars changed Load: %+v/%v -> %+v/%v", base.cfg, base.err, envRes.cfg, envRes.err)
		}

		if base.err != nil {
			msg := base.err.Error()
			if strings.Contains(msg, cfgSecretSentinel) {
				t.Fatalf("secret echo: Load error contains the sentinel: %q\nfile:\n%s", msg, block.String())
			}
			// Host echo is checked through the sentinel the generator appends
			// to a third of the hosts. A plain substring check on every host
			// is unsound: a short host can occur inside the service name,
			// which the error echoes by design (fuzz corpus 7fef62da).
		}

		if g.unsafePerm {
			if base.err != nil || !reflect.DeepEqual(*base.cfg, defaults) {
				t.Fatalf("unsafe-file gate: group-writable implicit config was not ignored: %+v / %v", base.cfg, base.err)
			}
			return
		}

		want := g.want
		if verr := want.Validate(); verr != nil {
			if base.err == nil {
				t.Fatalf("precedence model: expected an invalid-config error (%v), Load returned %+v\nfile:\n%s", verr, base.cfg, block.String())
			}
			return
		}
		if base.err != nil || base.cfg == nil {
			t.Fatalf("precedence model: valid config rejected: %v\nfile:\n%s", base.err, block.String())
		}
		got := *base.cfg
		if !g.securitySet {
			got.Security, want.Security = SecurityConfig{}, SecurityConfig{} // NET1-F4, see file comment
		}
		if len(want.Services) == 0 && len(got.Services) == 0 {
			got.Services, want.Services = nil, nil
		}
		if len(want.Security.AllowedPorts) == 0 && len(got.Security.AllowedPorts) == 0 {
			got.Security.AllowedPorts, want.Security.AllowedPorts = nil, nil
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("precedence model mismatch\nfile:\n%s\ngot:  %+v\nwant: %+v", block.String(), got, want)
		}
	})
}

// TestReproLoadDropsSecurityDefaults is NET1-F4's red half: a $HOME config
// that sets only a threshold silently zeroes every Security default
// (AllowedPorts empty, SSH failed-login thresholds 0), because Load registers
// SetDefault for thresholds/logs only. Gated: fails on the current tree.
func TestReproLoadDropsSecurityDefaults(t *testing.T) {
	if os.Getenv("DSD_NET1_REPRO") != "1" {
		t.Skip("red half of the NET1-F4 proof; set DSD_NET1_REPRO=1 (fails on the current tree)")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	r := loadWith(t, home, "thresholds:\n  disk_warn_pct: 70\n", 0o600)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if !reflect.DeepEqual(r.cfg.Security, defaults.Security) {
		t.Errorf("Security after a thresholds-only config = %+v, want defaults %+v", r.cfg.Security, defaults.Security)
	}
}

// Green half: with no config file at all, Security is the default — the
// oracle itself is sound.
func TestReproLoadDropsSecurityDefaults_NoFileGreen(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Security, defaults.Security) {
		t.Fatalf("no-file Security = %+v", cfg.Security)
	}
}
