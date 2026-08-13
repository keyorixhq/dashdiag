package render

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// writeReportFileNoFollow writes data to path, refusing to follow an existing
// symlink there. The report generators in this package (fleet_html.go,
// wave_html.go) derive a fully predictable filename (a second-resolution
// timestamp) and write it into the current working directory with plain
// os.WriteFile, which opens with O_CREATE|O_TRUNC and follows an existing
// symlink at that path rather than refusing it. If the report command is run
// from a shared/world-writable working directory (a cron job's scratch dir, a
// shared CI workspace), another local user can pre-plant a symlink at the
// predictable filename pointing at a file the report-generating user can
// write but the attacker cannot, and the report write would silently clobber
// that target. syscall.O_NOFOLLOW makes the open() itself refuse a symlink
// atomically (no separate Lstat-then-open TOCTOU window) while still letting
// a re-run overwrite a prior REGULAR-file report at the same path — the
// common case. Mirrors cmd/root.go's createOutFile, which guards --out the
// same way.
func writeReportFileNoFollow(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm) // #nosec G304 -- O_NOFOLLOW blocks symlink-follow
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
