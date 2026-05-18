//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// EntropyCollector reads the kernel entropy pool directly from /proc.
// Low entropy silently breaks crypto operations — TLS handshakes, key generation,
// random token creation all fail or block when entropy is exhausted.
type EntropyCollector struct{}

func NewEntropyCollector() *EntropyCollector { return &EntropyCollector{} }

func (c *EntropyCollector) Name() string           { return "Entropy" }
func (c *EntropyCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *EntropyCollector) Collect(_ context.Context) (interface{}, error) {
	avail, err := readProcInt("/proc/sys/kernel/random/entropy_avail")
	if err != nil {
		return nil, fmt.Errorf("reading entropy_avail: %w", err)
	}
	poolSize, _ := readProcInt("/proc/sys/kernel/random/poolsize")
	return &models.EntropyInfo{
		Available:   true,
		EntropyBits: avail,
		PoolSize:    poolSize,
	}, nil
}

func readProcInt(path string) (int, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a hardcoded /proc constant
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", path, err)
	}
	return v, nil
}
