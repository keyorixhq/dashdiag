//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// MongoDBAvailable is false off Linux — the probe is Linux-only.
func MongoDBAvailable() bool { return false }

type MongoDBCollector struct{}

func NewMongoDBCollector() *MongoDBCollector { return &MongoDBCollector{} }

func (c *MongoDBCollector) Name() string           { return "MongoDB" }
func (c *MongoDBCollector) Timeout() time.Duration { return time.Second }
func (c *MongoDBCollector) Collect(_ context.Context) (any, error) {
	return &models.MongoDBInfo{Detected: false}, nil
}
