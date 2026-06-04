//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type SteamOSCollector struct{ Deep bool }

func NewSteamOSCollector() *SteamOSCollector     { return &SteamOSCollector{} }
func NewSteamOSDeepCollector() *SteamOSCollector { return &SteamOSCollector{Deep: true} }

func (c *SteamOSCollector) Name() string           { return "SteamOS" }
func (c *SteamOSCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *SteamOSCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.SteamOSInfo{}, nil
}

// SteamOSAvailable returns false on non-Linux platforms — SteamOS is Linux only.
func SteamOSAvailable() bool { return false }
