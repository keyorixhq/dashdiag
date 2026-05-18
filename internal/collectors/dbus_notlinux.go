//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// DBusCollector is a no-op on non-Linux platforms.
type DBusCollector struct{}

func NewDBusCollector() *DBusCollector          { return &DBusCollector{} }
func (c *DBusCollector) Name() string           { return "DBus" }
func (c *DBusCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *DBusCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.DBusInfo{Active: true, Status: "n/a"}, nil
}
