//go:build linux || darwin

package source

import "syscall"

func (l Live) Statfs(path string) (StatfsInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return StatfsInfo{}, err
	}
	// uint64() casts normalise field types that differ across linux/darwin
	// (e.g. Bsize is int64 on linux, uint32 on darwin).
	return StatfsInfo{
		Bsize:  uint64(st.Bsize), //nolint:unconvert,gosec // cross-platform field-type normalisation
		Blocks: uint64(st.Blocks),
		Bfree:  uint64(st.Bfree),
		Bavail: uint64(st.Bavail),
		Files:  uint64(st.Files),
		Ffree:  uint64(st.Ffree),
	}, nil
}
