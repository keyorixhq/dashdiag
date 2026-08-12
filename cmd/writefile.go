package cmd

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// writeFileNoFollow writes data to path, refusing to follow an existing
// symlink there — the O_TRUNC-without-O_EXCL pattern os.WriteFile uses
// silently overwrites a symlink's TARGET rather than the symlink itself.
// Mirrors createOutFile below (--out) and internal/render's
// writeReportFileNoFollow; used by any cmd/ writer whose destination path is
// predictable/fixed (a hostname-derived report filename, a fixed hook script
// path) rather than a random temp name.
func writeFileNoFollow(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm) // #nosec G304 -- O_NOFOLLOW blocks symlink-follow
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("refusing to write through a symlink at %q", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
