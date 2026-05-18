//go:build !linux && !darwin

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type AuthCollector struct{}

func NewAuthCollector() *AuthCollector          { return &AuthCollector{} }
func (c *AuthCollector) Name() string           { return "Auth" }
func (c *AuthCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *AuthCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.AuthInfo{}, nil
}
