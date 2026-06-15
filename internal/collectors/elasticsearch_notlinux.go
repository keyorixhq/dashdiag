//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ElasticsearchAvailable is false off Linux — the probe is Linux-only.
func ElasticsearchAvailable() bool { return false }

type ElasticsearchCollector struct{}

func NewElasticsearchCollector() *ElasticsearchCollector { return &ElasticsearchCollector{} }

func (c *ElasticsearchCollector) Name() string           { return "Elasticsearch" }
func (c *ElasticsearchCollector) Timeout() time.Duration { return time.Second }
func (c *ElasticsearchCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.ElasticsearchInfo{Detected: false}, nil
}
