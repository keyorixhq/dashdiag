package render

import "errors"

// errWriter is an io.Writer that always returns an error. Used in tests to
// exercise error-propagation paths where the underlying writer fails.
type errWriter struct{}

func (*errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}
