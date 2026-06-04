//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// collectSteamOSWifi is a no-op on non-Linux — the network collector compiles on
// all platforms but only calls this when SteamOSAvailable() (always false here).
func collectSteamOSWifi(_ context.Context) *models.SteamOSWifi { return nil }

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
