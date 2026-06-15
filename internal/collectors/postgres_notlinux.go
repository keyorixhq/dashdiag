//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PostgresAvailable is false off Linux — the local-socket probe is Linux-only.
func PostgresAvailable() bool { return false }

type PostgresCollector struct{}

func NewPostgresCollector() *PostgresCollector { return &PostgresCollector{} }

func (c *PostgresCollector) Name() string           { return "Postgres" }
func (c *PostgresCollector) Timeout() time.Duration { return time.Second }
func (c *PostgresCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.PostgresInfo{Detected: false}, nil
}
