//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type PostBootCollector struct{}

func NewPostBootCollector() *PostBootCollector      { return &PostBootCollector{} }
func (c *PostBootCollector) Name() string           { return "PostBoot" }
func (c *PostBootCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *PostBootCollector) Collect(_ context.Context) (any, error) {
	return &models.PostBootInfo{}, nil
}

// PostBootAvailable is always false off Linux — prior-boot forensics read the Linux
// journal / wtmp, which don't exist elsewhere.
func PostBootAvailable() bool { return false }
