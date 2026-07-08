//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// MySQLAvailable is false off Linux — the local-socket probe is Linux-only.
func MySQLAvailable() bool { return false }

type MySQLCollector struct{}

func NewMySQLCollector() *MySQLCollector { return &MySQLCollector{} }

func (c *MySQLCollector) Name() string           { return "MySQL" }
func (c *MySQLCollector) Timeout() time.Duration { return time.Second }
func (c *MySQLCollector) Collect(_ context.Context) (any, error) {
	return &models.MySQLInfo{Detected: false}, nil
}
