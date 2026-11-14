package output

// qr_roundtrip_fuzz_test.go — FuzzQRCodeRoundTrip: encode round-trip of
// skip2/go-qrcode as DashDiag calls it (PrintQRCode: SanitizeControl, then
// qrcode.New(url, Medium), then ToString(false) to the terminal), decoded by
// an independent harness-side QR decoder, because the offline module cache
// has no QR decoder (no gozxing / tuotoo / liyue201).
//
// Who controls the bytes: today nobody — the only caller
// (cmd/health.go printHealthFooter) passes shareURL == "" and PrintQRCode
// returns before encoding. PrintQRCode's own comment anticipates a
// share-link server response once --share is wired, so the input is treated
// as network-controlled.
//
// Oracles:
//  1. Round-trip (PrintQRCode path): the block-art PrintQRCode writes, parsed
//     back into modules and decoded, equals SanitizeControl(url); the
//     trailing URL line equals it too; no C0/C1 control rune reaches stdout.
//  2. Round-trip (library, all four EC levels): Bitmap() decodes to content.
//  3. Standard conformance: format info (both copies) and version info (both
//     copies, v>=7) are valid BCH codewords that agree; the quiet zone is 4
//     light modules; every Reed-Solomon block has all-zero syndromes.
//  4. Bounded size: VersionNumber in 1..40 and the bitmap is 17+4v+8 square;
//     content of <= 100 bytes needs at most version 10 at any level (byte-
//     mode capacity of 10-H is 119 bytes; a mixed-mode optimiser must never
//     do worse than pure byte mode); encode+render of <= 3000 bytes finishes
//     within 2s.
//  5. Idempotence: Bitmap() called twice returns the same matrix (Bitmap
//     re-runs encode(), which appends terminator/padding to internal state).
//
// What this does NOT verify: the decoder handles versions 1-10 only (EC
// block table typed in from ISO/IEC 18004 Table 9 for v1-10; self-checked by
// the RS syndromes and the module count) — longer content is checked for
// bounds and idempotence only; scanning robustness (no image noise,
// rotation, real camera decoder); Kanji/ECI modes (go-qrcode never emits
// them); whether the mask chosen is the penalty-optimal one; ToSmallString
// and the PNG/Image paths (DashDiag does not use them).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"
)

// ── independent decoder ────────────────────────────────────────────────────

type qrBlockGroup struct{ n, total, data int }

// qrECTable[version][level] — level index: 0=L 1=M 2=Q 3=H. ISO 18004 Table 9.
var qrECTable = map[int][4][]qrBlockGroup{
	1:  {{{1, 26, 19}}, {{1, 26, 16}}, {{1, 26, 13}}, {{1, 26, 9}}},
	2:  {{{1, 44, 34}}, {{1, 44, 28}}, {{1, 44, 22}}, {{1, 44, 16}}},
	3:  {{{1, 70, 55}}, {{1, 70, 44}}, {{2, 35, 17}}, {{2, 35, 13}}},
	4:  {{{1, 100, 80}}, {{2, 50, 32}}, {{2, 50, 24}}, {{4, 25, 9}}},
	5:  {{{1, 134, 108}}, {{2, 67, 43}}, {{2, 33, 15}, {2, 34, 16}}, {{2, 33, 11}, {2, 34, 12}}},
	6:  {{{2, 86, 68}}, {{4, 43, 27}}, {{4, 43, 19}}, {{4, 43, 15}}},
	7:  {{{2, 98, 78}}, {{4, 49, 31}}, {{2, 32, 14}, {4, 33, 15}}, {{4, 39, 13}, {1, 40, 14}}},
	8:  {{{2, 121, 97}}, {{2, 60, 38}, {2, 61, 39}}, {{4, 40, 18}, {2, 41, 19}}, {{4, 40, 14}, {2, 41, 15}}},
	9:  {{{2, 146, 116}}, {{3, 58, 36}, {2, 59, 37}}, {{4, 36, 16}, {4, 37, 17}}, {{4, 36, 12}, {4, 37, 13}}},
	10: {{{2, 86, 68}, {2, 87, 69}}, {{4, 69, 43}, {1, 70, 44}}, {{6, 43, 19}, {2, 44, 20}}, {{6, 43, 15}, {2, 44, 16}}},
}

var qrAlign = map[int][]int{
	1: nil, 2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34},
	7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46}, 10: {6, 28, 50},
}

// format-info EC bits (ISO): L=01 M=00 Q=11 H=10 -> our level index.
var qrFormatLevel = map[int]int{1: 0, 0: 1, 3: 2, 2: 3}

func qrBCHFormat(data int) int {
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	return (data<<10 | rem&0x3ff) ^ 0x5412
}

func qrBCHVersion(v int) int {
	rem := v
	for range 12 {
		rem = rem<<1 ^ (rem>>11)*0x1f25
	}
	return v<<12 | rem&0xfff
}

func qrMaskBit(mask, y, x int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

// GF(256) with the QR polynomial 0x11d.
var qrExp, qrLog = func() ([512]byte, [256]int) {
	var e [512]byte
	var l [256]int
	x := 1
	for i := range 255 {
		e[i] = byte(x)
		l[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		e[i] = e[i-255]
	}
	return e, l
}()

func qrGFMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return qrExp[qrLog[a]+qrLog[b]]
}

// qrSyndromesZero evaluates the codeword polynomial at alpha^0..alpha^(ec-1).
func qrSyndromesZero(cw []byte, ec int) bool {
	for k := range ec {
		var s byte
		alpha := qrExp[k]
		for _, c := range cw {
			s = qrGFMul(s, alpha) ^ c
		}
		if s != 0 {
			return false
		}
	}
	return true
}

type qrDecoded struct {
	version, level, mask int
	content              []byte
}

// qrDecodeBitmap decodes a go-qrcode Bitmap() (with quiet zone).
func qrDecodeBitmap(bm [][]bool) (qrDecoded, error) {
	var d qrDecoded
	full := len(bm)
	for _, row := range bm {
		if len(row) != full {
			return d, errors.New("bitmap not square")
		}
	}
	const quiet = 4
	size := full - 2*quiet
	if size < 21 || (size-17)%4 != 0 {
		return d, fmt.Errorf("bitmap size %d is not 17+4v+8", full)
	}
	for y := range full {
		for x := range full {
			if (y < quiet || y >= full-quiet || x < quiet || x >= full-quiet) && bm[y][x] {
				return d, fmt.Errorf("quiet zone module (%d,%d) is dark", x, y)
			}
		}
	}
	d.version = (size - 17) / 4
	at := func(x, y int) bool { return bm[y+quiet][x+quiet] }

	// Format info, both copies.
	var f1, f2 int
	for i := range 6 {
		f1 |= b2i(at(8, i)) << i
	}
	f1 |= b2i(at(8, 7)) << 6
	f1 |= b2i(at(8, 8)) << 7
	f1 |= b2i(at(7, 8)) << 8
	for i := 9; i < 15; i++ {
		f1 |= b2i(at(14-i, 8)) << i
	}
	for i := range 8 {
		f2 |= b2i(at(size-1-i, 8)) << i
	}
	for i := 8; i < 15; i++ {
		f2 |= b2i(at(8, size-15+i)) << i
	}
	if f1 != f2 {
		return d, fmt.Errorf("format info copies differ: %015b vs %015b", f1, f2)
	}
	fdata := -1
	for c := range 32 {
		if qrBCHFormat(c) == f1 {
			fdata = c
		}
	}
	if fdata < 0 {
		return d, fmt.Errorf("format info %015b is not a valid BCH codeword", f1)
	}
	d.level, d.mask = qrFormatLevel[fdata>>3], fdata&7
	if !at(8, size-8) {
		return d, errors.New("dark module missing")
	}

	if d.version >= 7 {
		var v1, v2 int
		for i := range 18 {
			a, b := size-11+i%3, i/3
			v1 |= b2i(at(a, b)) << i
			v2 |= b2i(at(b, a)) << i
		}
		if v1 != v2 || v1 != qrBCHVersion(d.version) {
			return d, fmt.Errorf("version info %018b/%018b invalid for v%d", v1, v2, d.version)
		}
	}
	groups, ok := qrECTable[d.version]
	if !ok {
		return d, fmt.Errorf("decoder covers v1-10 only, got v%d", d.version)
	}

	// Function-pattern map.
	fn := make([][]bool, size)
	for i := range fn {
		fn[i] = make([]bool, size)
	}
	mark := func(x0, y0, w, h int) {
		for y := y0; y < y0+h; y++ {
			for x := x0; x < x0+w; x++ {
				if x >= 0 && y >= 0 && x < size && y < size {
					fn[y][x] = true
				}
			}
		}
	}
	mark(0, 0, 9, 9)
	mark(size-8, 0, 8, 9)
	mark(0, size-8, 9, 8)
	mark(6, 0, 1, size)
	mark(0, 6, size, 1)
	al := qrAlign[d.version]
	for i, ay := range al {
		for j, ax := range al {
			if (i == 0 && j == 0) || (i == 0 && j == len(al)-1) || (i == len(al)-1 && j == 0) {
				continue
			}
			mark(ax-2, ay-2, 5, 5)
		}
	}
	if d.version >= 7 {
		mark(size-11, 0, 3, 6)
		mark(0, size-11, 6, 3)
	}

	var bits []bool
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := range size {
			for j := range 2 {
				x := right - j
				upward := (right+1)&2 == 0
				y := vert
				if upward {
					y = size - 1 - vert
				}
				if !fn[y][x] {
					bits = append(bits, at(x, y) != qrMaskBit(d.mask, y, x))
				}
			}
		}
	}
	lvl := groups[d.level]
	total := 0
	for _, g := range lvl {
		total += g.n * g.total
	}
	if len(bits)/8 != total {
		return d, fmt.Errorf("v%d: %d data modules -> %d codewords, table says %d", d.version, len(bits), len(bits)/8, total)
	}
	cws := make([]byte, total)
	for i := range cws {
		for k := range 8 {
			cws[i] = cws[i]<<1 | byte(b2i(bits[i*8+k]))
		}
	}

	type blk struct {
		data, ec []byte
		nd       int
	}
	var blocks []*blk
	for _, g := range lvl {
		for range g.n {
			blocks = append(blocks, &blk{nd: g.data})
		}
	}
	ecLen := lvl[0].total - lvl[0].data
	p := 0
	for i := 0; ; i++ {
		any := false
		for _, b := range blocks {
			if i < b.nd {
				b.data = append(b.data, cws[p])
				p++
				any = true
			}
		}
		if !any {
			break
		}
	}
	for range ecLen {
		for _, b := range blocks {
			b.ec = append(b.ec, cws[p])
			p++
		}
	}
	var data []byte
	for bi, b := range blocks {
		if !qrSyndromesZero(append(append([]byte(nil), b.data...), b.ec...), ecLen) {
			return d, fmt.Errorf("RS block %d has non-zero syndromes", bi)
		}
		data = append(data, b.data...)
	}

	// Segments.
	br := &qrBitReader{b: data}
	const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
	small := d.version <= 9
	for br.left() >= 4 {
		mode := br.read(4)
		switch mode {
		case 0:
			return d, nil
		case 1:
			n := br.read(map[bool]int{true: 10, false: 12}[small])
			for n >= 3 {
				v := br.read(10)
				if v > 999 {
					return d, fmt.Errorf("numeric triple %d", v)
				}
				d.content = fmt.Appendf(d.content, "%03d", v)
				n -= 3
			}
			if n == 2 {
				v := br.read(7)
				if v > 99 {
					return d, fmt.Errorf("numeric pair %d", v)
				}
				d.content = fmt.Appendf(d.content, "%02d", v)
			} else if n == 1 {
				v := br.read(4)
				if v > 9 {
					return d, fmt.Errorf("numeric digit %d", v)
				}
				d.content = fmt.Appendf(d.content, "%d", v)
			}
		case 2:
			n := br.read(map[bool]int{true: 9, false: 11}[small])
			for n >= 2 {
				v := br.read(11)
				if v >= 45*45 {
					return d, fmt.Errorf("alnum pair %d", v)
				}
				d.content = append(d.content, alnum[v/45], alnum[v%45])
				n -= 2
			}
			if n == 1 {
				v := br.read(6)
				if v >= 45 {
					return d, fmt.Errorf("alnum char %d", v)
				}
				d.content = append(d.content, alnum[v])
			}
		case 4:
			n := br.read(map[bool]int{true: 8, false: 16}[small])
			for range n {
				d.content = append(d.content, byte(br.read(8)))
			}
		default:
			return d, fmt.Errorf("unexpected mode indicator %04b", mode)
		}
		if br.over {
			return d, errors.New("segment runs past the data codewords")
		}
	}
	return d, nil
}

type qrBitReader struct {
	b    []byte
	pos  int
	over bool
}

func (r *qrBitReader) left() int { return len(r.b)*8 - r.pos }

func (r *qrBitReader) read(n int) int {
	v := 0
	for range n {
		if r.pos >= len(r.b)*8 {
			r.over = true
			return v
		}
		bit := r.b[r.pos/8] >> (7 - r.pos%8) & 1
		v = v<<1 | int(bit)
		r.pos++
	}
	return v
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// qrParseBlockArt inverts ToString(false): "  " = dark module, "██" = light.
func qrParseBlockArt(lines []string) ([][]bool, error) {
	var bm [][]bool
	for _, ln := range lines {
		var row []bool
		for ln != "" {
			switch {
			case strings.HasPrefix(ln, "  "):
				row = append(row, true)
				ln = ln[2:]
			case strings.HasPrefix(ln, "██"):
				row = append(row, false)
				ln = ln[len("██"):]
			default:
				return nil, fmt.Errorf("unexpected block-art text %q", ln)
			}
		}
		bm = append(bm, row)
	}
	return bm, nil
}

// captureStdoutConcurrent is captureStdout with a concurrent reader, so a
// large QR rendering cannot fill the pipe and block the writer.
func captureStdoutConcurrent(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(rd)
		done <- data
	}()
	os.Stdout = wr
	defer func() { os.Stdout = old }()
	fn()
	_ = wr.Close()
	out := <-done
	_ = rd.Close()
	return string(out)
}

var qrLevels = []qrcode.RecoveryLevel{qrcode.Low, qrcode.Medium, qrcode.High, qrcode.Highest}

// qrLevelIndex maps go-qrcode's level to the ISO table index L,M,Q,H.
func qrLevelIndex(l qrcode.RecoveryLevel) int {
	switch l {
	case qrcode.Low:
		return 0
	case qrcode.Medium:
		return 1
	case qrcode.High:
		return 2
	}
	return 3
}

func FuzzQRCodeRoundTrip(f *testing.F) {
	f.Add("https://share.example.com/r/abc123", uint8(1))
	f.Add("HTTPS://EXAMPLE.COM/ABC", uint8(0))
	f.Add("0123456789012345678901234567890", uint8(3))
	f.Add("https://e.x/\x1b[2J\x07evil\u0085", uint8(2))
	f.Add("A1b2 $%*+-./:", uint8(1))
	f.Add(strings.Repeat("9", 100), uint8(3))
	f.Add(strings.Repeat("é", 50), uint8(3))
	f.Add("\xff\xfe", uint8(1))
	f.Add(strings.Repeat("x", 2500), uint8(1))

	f.Fuzz(func(t *testing.T, url string, lvl uint8) {
		if len(url) > 3000 {
			return
		}
		level := qrLevels[int(lvl)%len(qrLevels)]

		// Library path, every EC level.
		start := time.Now()
		q, err := qrcode.New(url, level)
		if err != nil {
			// go-qrcode rejects empty content ("no data to encode") by design;
			// PrintQRCode returns before encoding an empty url.
			if url != "" && len(url) <= 100 {
				t.Fatalf("bounded size: %d-byte content rejected at level %d: %v", len(url), level, err)
			}
		} else {
			// Deep-copy the first matrix: Bitmap() may hand out storage that a
			// later call rewrites, which would make the comparison vacuous.
			bm := qrCloneBitmap(q.Bitmap())
			bm2 := q.Bitmap()
			if time.Since(start) > 2*time.Second {
				t.Fatalf("bounded work: encode+render of %d bytes took %v", len(url), time.Since(start))
			}
			if q.VersionNumber < 1 || q.VersionNumber > 40 || len(bm) != 17+4*q.VersionNumber+8 {
				t.Fatalf("bounded size: version %d, bitmap %d", q.VersionNumber, len(bm))
			}
			if len(url) <= 100 && q.VersionNumber > 10 {
				t.Fatalf("bounded size: %d bytes needed version %d > 10 at level %d", len(url), q.VersionNumber, level)
			}
			if !qrBitmapsEqual(bm, bm2) {
				t.Fatalf("idempotence: second Bitmap() differs for %q", url)
			}
			if q.VersionNumber <= 10 {
				dec, derr := qrDecodeBitmap(bm)
				if derr != nil {
					t.Fatalf("conformance: %q (v%d level %d): %v", url, q.VersionNumber, level, derr)
				}
				if dec.level != qrLevelIndex(level) {
					t.Fatalf("format info says level %d, encoded with %d", dec.level, qrLevelIndex(level))
				}
				if !bytes.Equal(dec.content, []byte(url)) {
					t.Fatalf("round-trip: encoded %q, decoded %q", url, dec.content)
				}
			}
		}

		// DashDiag path: PrintQRCode in an interactive human-mode session.
		if len(url) > 400 {
			return
		}
		var out string
		withTTY(t, true, func() {
			out = captureStdoutConcurrent(t, func() { _ = PrintQRCode(url, ModeHuman) })
		})
		if url == "" {
			if out != "" {
				t.Fatalf("empty url produced output %q", out)
			}
			return
		}
		for _, r := range out {
			if r != '\n' && unicode.IsControl(r) {
				t.Fatalf("control rune %U reached stdout for %q", r, url)
			}
		}
		want := SanitizeControl(url)
		if want == "" {
			// NET1-F5 (TestReproPrintQRCodeAllControlURL): the empty check
			// runs before sanitizing, so an all-control url prints a dangling
			// "QR: " line. Reproduced separately; not re-found here.
			return
		}
		if !utf8.ValidString(out) {
			t.Fatalf("stdout is not valid UTF-8 for %q", url)
		}
		if after, ok := strings.CutPrefix(out, "QR: "); ok {
			if len(want) <= 100 {
				t.Fatalf("PrintQRCode fell back to text for a %d-byte url", len(want))
			}
			if after != want+"\n" {
				t.Fatalf("fallback line %q, want %q", after, want)
			}
			return
		}
		art, tail, ok := strings.Cut(out, "\n\n")
		if !ok || tail != want+"\n" {
			t.Fatalf("PrintQRCode output shape: tail %q, want %q", tail, want+"\n")
		}
		bm, perr := qrParseBlockArt(strings.Split(art, "\n"))
		if perr != nil {
			t.Fatalf("block art: %v", perr)
		}
		if (len(bm)-8-17)/4 > 10 {
			return // beyond the decoder's version table; bounds checked above
		}
		dec, derr := qrDecodeBitmap(bm)
		if derr != nil {
			t.Fatalf("conformance (PrintQRCode art) for %q: %v", url, derr)
		}
		if dec.level != 1 {
			t.Fatalf("PrintQRCode encoded at level %d, want Medium", dec.level)
		}
		if string(dec.content) != want {
			t.Fatalf("round-trip (PrintQRCode): url %q sanitized %q, QR decodes to %q", url, want, dec.content)
		}
	})
}

// TestReproPrintQRCodeAllControlURL is NET1-F5's red half: PrintQRCode's
// empty-url guard runs before SanitizeControl, so a url made only of control
// runes (e.g. a share server answering "\x1b\x07") sanitizes to "", fails
// qrcode.New, and prints a dangling "QR: " line. Oracle: a url that
// sanitizes to empty prints nothing, the same as the empty url. Gated: fails
// on the current tree.
func TestReproPrintQRCodeAllControlURL(t *testing.T) {
	if os.Getenv("DSD_NET1_REPRO") != "1" {
		t.Skip("red half of the NET1-F5 proof; set DSD_NET1_REPRO=1 (fails on the current tree)")
	}
	withTTY(t, true, func() {
		out := captureStdoutConcurrent(t, func() { _ = PrintQRCode("\x1b\x07\u0085", ModeHuman) })
		if out != "" {
			t.Errorf("all-control url printed %q, want nothing", out)
		}
	})
}

// Green half: the oracle holds for the genuinely empty url.
func TestReproPrintQRCodeAllControlURL_EmptyGreen(t *testing.T) {
	withTTY(t, true, func() {
		if out := captureStdoutConcurrent(t, func() { _ = PrintQRCode("", ModeHuman) }); out != "" {
			t.Fatalf("empty url printed %q", out)
		}
	})
}

func qrCloneBitmap(bm [][]bool) [][]bool {
	out := make([][]bool, len(bm))
	for i, row := range bm {
		out[i] = append([]bool(nil), row...)
	}
	return out
}

func qrBitmapsEqual(a, b [][]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
