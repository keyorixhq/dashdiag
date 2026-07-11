package cmd

// truncateStr truncates a string to at most n runes with an ellipsis. It slices
// by rune, not byte, so a multibyte character at the boundary is never split
// into invalid UTF-8.
func truncateStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
