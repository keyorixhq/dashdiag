package source

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// GlobParentDir returns the deepest directory of pattern that contains no glob
// metacharacter: the directory whose readability decides whether an empty Glob
// result means "nothing there" or "could not look". For
// "/etc/letsencrypt/live/*/cert.pem" that is "/etc/letsencrypt/live" (the
// literal parent of the first wildcard), not the wildcard path itself.
func GlobParentDir(pattern string) string {
	dir := filepath.Dir(pattern)
	for strings.ContainsAny(dir, `*?[\`) {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return dir
}

// GlobChecked expands pattern through src and, unlike src.Glob, distinguishes
// "genuinely no matches" from "the pattern's directory could not be read".
// filepath.Glob (which Live.Glob wraps) swallows a permission-denied error on
// the pattern's base directory as a nil-error EMPTY result: per the stdlib doc
// "The only possible returned error is ErrBadPattern". A caller checking only
// len(matches)==0 therefore cannot tell an empty, readable directory from one
// it was denied access to, and reports the second as a clean "none found".
//
// ReadDir is consulted only when matches come back empty (a non-empty result
// already proves the directory was readable). dirUnreadable is true only for a
// genuine permission error, not for a directory that does not exist: ENOENT is
// a normal "not present" case, distinct from "could not verify".
//
// This is the only sanctioned way to glob in production code; the AST guard in
// internal/collectors (TestNoRawGlobInProduction) fails on filepath.Glob and
// on the collectors' raw glob() helper elsewhere.
func GlobChecked(src Source, pattern string) (matches []string, dirUnreadable bool, err error) {
	matches, err = src.Glob(pattern)
	if err != nil {
		return nil, false, err
	}
	if len(matches) > 0 {
		return matches, false, nil
	}
	if _, dirErr := src.ReadDir(GlobParentDir(pattern)); dirErr != nil && errors.Is(dirErr, os.ErrPermission) {
		return matches, true, nil
	}
	return matches, false, nil
}
