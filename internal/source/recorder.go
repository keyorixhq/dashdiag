package source

import "context"

// Recorder wraps an inner Source and tees every read and exec into a Bundle while
// forwarding the real result unchanged. Capture is transparent: collectors behave
// exactly as they would against the inner Source.
type Recorder struct {
	inner Source
	b     *Bundle
}

// NewRecorder returns a Recorder over inner (typically Live{}).
func NewRecorder(inner Source) *Recorder {
	return &Recorder{inner: inner, b: NewBundle()}
}

// Bundle returns the accumulating capture. Call after collection completes.
func (r *Recorder) Bundle() *Bundle { return r.b }

func (r *Recorder) ReadFile(path string) ([]byte, error) {
	data, err := r.inner.ReadFile(path)
	r.b.putFile(path, data, err)
	return data, err
}

func (r *Recorder) Glob(pattern string) ([]string, error) {
	m, err := r.inner.Glob(pattern)
	if err == nil {
		r.b.putGlob(pattern, m)
	}
	return m, err
}

func (r *Recorder) ReadDir(dir string) ([]string, error) {
	names, err := r.inner.ReadDir(dir)
	if err == nil {
		r.b.putDir(dir, names)
	}
	return names, err
}

func (r *Recorder) Readlink(path string) (string, error) {
	target, err := r.inner.Readlink(path)
	r.b.putLink(path, target, err)
	return target, err
}

func (r *Recorder) Stat(path string) (FileMeta, error) {
	meta, err := r.inner.Stat(path)
	r.b.putStat(path, meta, err)
	return meta, err
}

func (r *Recorder) Run(ctx context.Context, name string, args ...string) (Result, error) {
	res, err := r.inner.Run(ctx, name, args...)
	r.b.putCmd(name, args, res, err)
	return res, err
}
