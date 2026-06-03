//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// BUG-020: inside an LXC/Docker container, SMART is irrelevant — smartctl is
// typically absent and the host owns the physical disks. With InContainer=true
// the SMART gate must skip every drive, so no drive ends up with a populated
// SMART result (which would surface a false "smartctl not installed" concern).
func TestDiskSMARTSuppressedInContainer(t *testing.T) {
	c := &DiskCollector{ContainerCtx: platform.ContainerContext{InContainer: true}}

	var result models.DiskInfo
	c.collectLinuxExtras(&result)

	for _, d := range result.Drives {
		if d.SMART != nil {
			t.Errorf("drive %q: SMART must be nil inside a container, got %+v", d.Name, d.SMART)
		}
	}
}
