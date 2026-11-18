// Package verify holds the scratch verification for the F1 --config size-cap
// proposal (.scratch/proposals/config-size-cap.patch). It imports BOTH the
// patched config copy (./config) and the production config package, and proves
// the patched Load rejects an over-size explicit --config while production does
// not. NOT part of the production build (lives under .scratch/).
package verify
