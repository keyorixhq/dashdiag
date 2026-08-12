package cvedata

import "io"

// maxDecompressedFeedBytes caps how much decompressed data a single CVE feed
// file (KEV catalog, OVAL XML, or a pre-converted snapshot) is allowed to
// decode before dsd gives up. Real feeds run from a few MB (KEV) to tens of
// MB (RHEL/SUSE/Ubuntu OVAL, decompressed); a gzip/bzip2 bomb — a small
// compressed file that decompresses to gigabytes — must not be able to
// exhaust memory just because dsd trusted the compression ratio. Wrapping the
// decompressing reader in an io.LimitReader before handing it to the
// json/xml decoder bounds it regardless of what the file claims to contain.
// A var (not const) so tests can shrink it rather than constructing an
// actual gigabyte-scale fixture to prove the cap works.
var maxDecompressedFeedBytes int64 = 512 * 1024 * 1024 // 512MiB

// boundDecompressed wraps r (a gzip/bzip2 reader, or a plain file reader for
// an uncompressed feed) so a decoder reading from it can never pull more than
// maxDecompressedFeedBytes out of a single feed file/stream.
func boundDecompressed(r io.Reader) io.Reader {
	return io.LimitReader(r, maxDecompressedFeedBytes)
}
