package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strings"
)

var (
	homePathRE = regexp.MustCompile(`(?:/Users/|/home/|[Cc]:[\\/]+Users[\\/]+)[A-Za-z0-9._-]+`)
	ipv4RE     = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
	ipv6RE     = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	urlRE      = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>()\[\]{}\x60\\]+`)
	emailRE    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
)

// Address ranges the ip rule lets through: loopback, unspecified and the
// documentation ranges.
var docPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
}

// Image names such as logo@2x.png have the shape of an address.
var imageTLDs = map[string]bool{"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "webp": true, "avif": true}

// Extensions the data-file rule refuses without a fixture: audio, video,
// model weights, datasets and archives.
var dataExts = map[string]bool{}

func init() {
	for _, e := range strings.Fields(`
		wav mp3 flac ogg oga opus m4a aac aif aiff wma amr caf pcm raw au snd mid midi
		mp4 m4v mov mkv webm avi
		gguf ggml bin safetensors pt pth ckpt onnx pb tflite mlmodel mlpackage npy npz h5 hdf5 pkl pickle joblib model
		csv tsv jsonl ndjson parquet arrow feather sqlite sqlite3 db duckdb
		zip tar gz tgz bz2 xz zst 7z rar lz4 lzma jar whl`) {
		dataExts[e] = true
	}
}

// textRules applies the line rules — home-path, ip, private-url, email,
// denylist — to data. With perLine false every finding is about the whole of
// data (a path) and carries line 0.
func textRules(dl *Denylist, authorAddr, where string, data []byte, perLine bool) []Finding {
	var out []Finding
	li := newLineIndex(data)
	add := func(off int, rule, match string) {
		ln := 0
		if perLine {
			ln = li.line(off)
		}
		out = append(out, Finding{where, ln, rule, match})
	}

	// Each regexp runs only when its literal anchor occurs: a large file
	// without one costs a byte search, not a regexp pass.
	has := func(lit string) bool { return bytes.Contains(data, []byte(lit)) }
	home := has("/home/") || bytes.Contains(bytes.ToLower(data), []byte("users"))
	for _, m := range findAll(home, homePathRE, data) {
		if m[0] > 0 && isPathWordByte(data[m[0]-1]) {
			continue
		}
		add(m[0], RuleHomePath, string(data[m[0]:m[1]]))
	}

	for _, m := range ipv4RE.FindAllIndex(data, -1) {
		if m[0] > 0 && (isAlnum(data[m[0]-1]) || data[m[0]-1] == '.' || data[m[0]-1] == '_') {
			continue
		}
		if m[1] < len(data) && (isDigit(data[m[1]]) || data[m[1]] == '.' && m[1]+1 < len(data) && isDigit(data[m[1]+1])) {
			continue
		}
		s := string(data[m[0]:m[1]])
		if a, err := netip.ParseAddr(s); err == nil && !publicSafe(a) {
			add(m[0], RuleIP, s)
		}
	}

	for _, m := range findAll(has(":"), ipv6RE, data) {
		if m[0] > 0 && (isAlnum(data[m[0]-1]) || data[m[0]-1] == '_') {
			continue
		}
		if m[1] < len(data) && (isAlnum(data[m[1]]) || data[m[1]] == '_') {
			continue
		}
		s := strings.TrimRight(string(data[m[0]:m[1]]), ".:")
		s = strings.TrimLeft(s, ".")
		if !looksLikeIPv6(s) {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Is6() && !publicSafe(a) {
			add(m[0], RuleIP, s)
		}
	}

	for _, m := range findAll(has("://"), urlRE, data) {
		u := strings.TrimRight(string(data[m[0]:m[1]]), ".,;:!?")
		scheme, rest, _ := strings.Cut(u, "://")
		if strings.Contains(strings.ToLower(scheme), "ssh") {
			add(m[0], RulePrivateURL, u)
			continue
		}
		if len(dl.matchesIn(urlHost(rest))) > 0 {
			add(m[0], RulePrivateURL, u)
		}
	}

	for _, m := range findAll(has("@"), emailRE, data) {
		if m[0] >= 3 && string(data[m[0]-3:m[0]]) == "://" {
			continue // userinfo of a URL, judged by the private-url rule
		}
		s := string(data[m[0]:m[1]])
		if strings.EqualFold(s, authorAddr) {
			continue
		}
		if tld := s[strings.LastIndexByte(s, '.')+1:]; imageTLDs[strings.ToLower(tld)] {
			continue
		}
		add(m[0], RuleEmail, s)
	}

	lowered := bytes.ToLower(data)
	lli := newLineIndex(lowered)
	for _, h := range dl.find(lowered) {
		ln := 0
		if perLine {
			ln = lli.line(h.off)
		}
		out = append(out, Finding{where, ln, RuleDenylist, token(h.n)})
	}
	return out
}

func findAll(ok bool, re *regexp.Regexp, data []byte) [][]int {
	if !ok {
		return nil
	}
	return re.FindAllIndex(data, -1)
}

// fileRules applies the rules about a file as a whole: data-file, link, size.
func fileRules(dl *Denylist, fixtures map[string]Fixture, f File) []Finding {
	var out []Finding
	var why []string
	dir := path.Dir(f.Path)
	for _, seg := range strings.Split(dir, "/") {
		if seg == "testdata" || seg == "defaults" {
			why = append(why, "under "+seg+"/")
			break
		}
	}
	if ext := strings.TrimPrefix(strings.ToLower(path.Ext(f.Path)), "."); dataExts[ext] {
		why = append(why, "extension ."+ext)
	}
	switch {
	case f.Mode == ModeSymlink:
		why = append(why, "symlink")
		if strings.Contains(string(f.Data), "annex/objects/") {
			why = append(why, "git-annex pointer")
		}
	case bytes.HasPrefix(f.Data, []byte("/annex/objects/")):
		why = append(why, "git-annex pointer")
	case isBinary(f.Data):
		why = append(why, "binary")
	}
	if len(why) > 0 && f.Mode != ModeGitlink {
		if fx, ok := fixtures[f.Path]; !ok {
			out = append(out, Finding{f.Path, 0, RuleDataFile, strings.Join(why, ", ") + ", no fixture entry"})
		} else if sum := sha256.Sum256(f.Data); !strings.EqualFold(fx.SHA256, hex.EncodeToString(sum[:])) {
			out = append(out, Finding{f.Path, 0, RuleDataFile, "sha256 differs from its fixture entry"})
		}
	}

	if f.Mode == ModeSymlink {
		t := string(f.Data)
		if path.IsAbs(t) || strings.HasPrefix(t, `\`) || len(t) > 1 && t[1] == ':' {
			out = append(out, Finding{f.Path, 0, RuleLink, t})
		} else if c := path.Clean(path.Join(path.Dir(f.Path), t)); c == ".." || strings.HasPrefix(c, "../") {
			out = append(out, Finding{f.Path, 0, RuleLink, t})
		}
	}
	if path.Base(f.Path) == ".gitmodules" {
		li := newLineIndex(f.Data)
		off := 0
		for _, line := range strings.SplitAfter(string(f.Data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok && strings.TrimSpace(k) == "url" && len(dl.matchesIn(v)) > 0 {
				out = append(out, Finding{f.Path, li.line(off), RuleLink, strings.TrimSpace(v)})
			}
			off += len(line)
		}
	}
	if len(f.Data) > MaxSize {
		out = append(out, Finding{f.Path, 0, RuleSize, fmt.Sprintf("%d bytes", len(f.Data))})
	}
	return out
}

func publicSafe(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() {
		return true
	}
	for _, p := range docPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// looksLikeIPv6 keeps candidates that read as an address, not a Python slice
// such as a[1::2]: three or more groups, or a group of three or more digits.
func looksLikeIPv6(s string) bool {
	if strings.Count(s, ":") < 2 {
		return false
	}
	groups, long := 0, false
	for _, g := range strings.Split(s, ":") {
		if g == "" {
			continue
		}
		groups++
		if len(g) >= 3 {
			long = true
		}
	}
	return groups >= 3 || long || s == "::"
}

// urlHost returns the host part of what follows "scheme://".
func urlHost(rest string) string {
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	return rest
}

// isBinary is git's test: a NUL byte in the first 8000 bytes.
func isBinary(b []byte) bool {
	if len(b) > 8000 {
		b = b[:8000]
	}
	return bytes.IndexByte(b, 0) >= 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isPathWordByte reports a byte that would make /home/… part of a longer
// path or URL rather than the start of a home directory.
func isPathWordByte(c byte) bool { return isAlnum(c) || c == '.' || c == '_' || c == '-' }
