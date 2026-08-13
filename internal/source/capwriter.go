package source

import "bytes"

// MaxCapturedOutput bounds how much stdout/stderr a single subprocess exec is
// willing to buffer in memory. Real diagnostic tools (docker, kubectl,
// journalctl, smartctl...) never legitimately emit more than a few MB even on
// a large fleet; a subprocess that emits far more — a compromised binary
// standing in for a trusted tool, or a pathological amount of container/pod
// output driven by attacker-controlled names — must not be able to exhaust
// dsd's memory just by writing to its own stdout/stderr.
const MaxCapturedOutput = 64 * 1024 * 1024 // 64MiB per stream

// CapWriter accumulates up to Limit bytes and silently discards anything past
// that, so streaming a subprocess's stdout/stderr into it can never allocate
// more than the cap regardless of how much the child process writes. Write
// always reports the full slice as consumed and never returns an error, so a
// capped writer never causes exec.Cmd to abort the command early or the
// subprocess to see a broken pipe.
type CapWriter struct {
	buf   bytes.Buffer
	Limit int
}

// NewCapWriter returns a CapWriter that keeps at most limit bytes.
func NewCapWriter(limit int) *CapWriter { return &CapWriter{Limit: limit} }

func (w *CapWriter) Write(p []byte) (int, error) {
	if remaining := w.Limit - w.buf.Len(); remaining > 0 {
		if remaining < len(p) {
			w.buf.Write(p[:remaining])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

// Bytes returns the bytes captured so far (at most Limit).
func (w *CapWriter) Bytes() []byte { return w.buf.Bytes() }
