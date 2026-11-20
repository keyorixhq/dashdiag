package collectors

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// sshdMaxIncludeDepth mirrors OpenSSH's READCONF_MAX_DEPTH: deeper Include
// chains are rejected by sshd, and the bound keeps an Include loop finite here.
const sshdMaxIncludeDepth = 16

// sshdAccumulatingKeys are the keywords sshd collects from every directive
// instead of keeping the first one (several AllowUsers lines add up).
var sshdAccumulatingKeys = map[string]bool{
	"allowusers": true, "allowgroups": true, "denyusers": true, "denygroups": true,
	"port": true, "listenaddress": true, "hostkey": true, "acceptenv": true,
}

// sshdConfigWalk replays sshd_config files the way sshd reads them (#1203):
// Include is expanded where it appears, Match blocks are skipped (a Match
// ends with the file it appears in, confirmed against sshd -T), and for each
// keyword only the first obtained value reaches apply. Last-wins parsing let a
// later "PasswordAuthentication no" hide an earlier "yes" that sshd applies.
type sshdConfigWalk struct {
	apply      func(key string, fields []string)
	seen       map[string]bool
	readAny    bool // at least one file was read
	sawInclude bool // a global Include directive was found
	unreadable bool // a file existed but could not be read (permission, size)
}

func newSSHDConfigWalk(apply func(key string, fields []string)) *sshdConfigWalk {
	return &sshdConfigWalk{apply: apply, seen: make(map[string]bool)}
}

// file reads one config file and walks it. It returns true when the file was
// read. A permission-denied or oversized file sets unreadable so callers say
// "couldn't audit SSH" rather than reporting the compiled defaults as real.
func (w *sshdConfigWalk) file(path string, depth int) bool {
	data, err := readFile(path) // #nosec G304 -- well-known config paths and their Includes
	if err != nil {
		if os.IsPermission(err) || errors.Is(err, errFileTooLarge) {
			w.unreadable = true
		}
		return false
	}
	w.readAny = true
	w.text(string(data), depth)
	return true
}

// text walks config content. depth is the Include nesting level of content.
func (w *sshdConfigWalk) text(content string, depth int) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	inMatch := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "match" {
			inMatch = !strings.EqualFold(fields[1], "all")
			continue
		}
		if inMatch {
			continue // conditional override, not the global policy
		}
		if key == "include" {
			w.include(fields[1:], depth)
			continue
		}
		if !sshdAccumulatingKeys[key] {
			if w.seen[key] {
				continue
			}
			w.seen[key] = true
		}
		w.apply(key, fields)
	}
}

// include expands Include patterns in place. Relative patterns are taken
// relative to /etc/ssh and matches are walked in lexical order, as sshd does.
func (w *sshdConfigWalk) include(patterns []string, depth int) {
	w.sawInclude = true
	if depth >= sshdMaxIncludeDepth {
		return
	}
	for _, p := range patterns {
		if !filepath.IsAbs(p) {
			p = filepath.Join("/etc/ssh", p)
		}
		files, dirUnreadable, err := globChecked(filepath.Clean(p))
		if dirUnreadable {
			w.unreadable = true // drop-ins exist but could not be listed
		}
		if err != nil {
			continue
		}
		sort.Strings(files)
		for _, f := range files {
			w.file(f, depth+1)
		}
	}
}
