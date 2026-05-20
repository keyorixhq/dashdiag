//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type BondingCollector struct{}

func NewBondingCollector() *BondingCollector       { return &BondingCollector{} }
func (c *BondingCollector) Name() string           { return "Bonding" }
func (c *BondingCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *BondingCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.BondingInfo{}, nil
}

func IsBondingPresent() bool { return false }

func collectBonds() []models.BondInterface { return nil }
