package collectors

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"
)

// Collector matches runner.Collector exactly.
type Collector interface {
	Name() string
	Timeout() time.Duration
	Collect(ctx context.Context) (interface{}, error)
}

// runCmd runs an external command with LC_ALL=C and LANG=C so numeric output
// always uses dot as the decimal separator regardless of the user's locale.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}
