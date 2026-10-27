//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// deniedBootSource reproduces filepath.Glob's behaviour on a 0700 /boot: the
// pattern matches nothing (no error), while a direct ReadDir shows the denial.
type deniedBootSource struct{ fakeLookPathStatfsSource }

func (deniedBootSource) Glob(string) ([]string, error) { return nil, nil }
func (deniedBootSource) ReadDir(dir string) ([]string, error) {
	if dir == "/boot" {
		return nil, fmt.Errorf("open /boot: %w", os.ErrPermission)
	}
	return nil, nil
}

// A permission-denied /boot must surface BootUnreadable, never a clean
// "0 kernels / not applicable".
func TestKernelRetentionCollector_UnreadableBootIsFlagged(t *testing.T) {
	prev := SetSource(deniedBootSource{fakeLookPathStatfsSource{
		Replay: source.NewReplay(source.NewBundle()),
		found:  map[string]bool{"dpkg": true},
	}})
	t.Cleanup(func() { SetSource(prev) })

	raw, err := NewKernelRetentionCollector(platform.ContainerContext{}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.KernelRetentionInfo)
	if !info.BootUnreadable {
		t.Errorf("BootUnreadable = false for a permission-denied /boot, got %+v", info)
	}
}
