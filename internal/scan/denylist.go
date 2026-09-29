package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrNoDenylist reports a denylist that is absent or has no entries. A check
// without the owner's private values cannot judge, so it must not read as clean.
var ErrNoDenylist = errors.New("denylist missing or empty")

// Denylist holds the owner's private values. Reports name an entry as
// "token #N", never by its value.
type Denylist struct {
	entries []dentry
	masker  *regexp.Regexp
}

type dentry struct {
	n     int    // 1-based position among the entries
	raw   string // the line as written, trimmed, `word:` prefix included
	lower string // the value to search for, lower-cased, prefix removed
	word  bool   // whole words only
}

// DenylistPath is $PUBMIRROR_DENYLIST, else ~/.config/pubmirror/denylist.txt.
func DenylistPath() (string, error) {
	if p := os.Getenv("PUBMIRROR_DENYLIST"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("denylist path: %w", err)
	}
	return filepath.Join(home, ".config", "pubmirror", "denylist.txt"), nil
}

// LoadDenylist reads the denylist at path. An absent or empty file is
// ErrNoDenylist.
func LoadDenylist(path string) (*Denylist, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s does not exist", ErrNoDenylist, path)
	}
	if err != nil {
		return nil, fmt.Errorf("denylist: %w", err)
	}
	d, err := ParseDenylist(data)
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, path)
	}
	return d, nil
}

// ParseDenylist parses denylist text: one entry per line, `#` starts a
// comment, blank lines are skipped, `word:<entry>` matches whole words only.
func ParseDenylist(data []byte) (*Denylist, error) {
	d := &Denylist{}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		e := dentry{n: len(d.entries) + 1, raw: line}
		v := line
		if rest, ok := strings.CutPrefix(line, "word:"); ok {
			e.word = true
			v = strings.TrimSpace(rest)
		}
		if v == "" {
			return nil, fmt.Errorf("denylist entry %d is empty after its prefix", e.n)
		}
		e.lower = strings.ToLower(v)
		d.entries = append(d.entries, e)
	}
	if len(d.entries) == 0 {
		return nil, fmt.Errorf("%w: no entries", ErrNoDenylist)
	}
	// The masker hides every entry, whole-word or not, longest first, so a
	// value never reaches a report through another rule's match.
	byLen := append([]dentry(nil), d.entries...)
	sort.SliceStable(byLen, func(i, j int) bool { return len(byLen[i].lower) > len(byLen[j].lower) })
	alts := make([]string, len(byLen))
	for i, e := range byLen {
		alts[i] = regexp.QuoteMeta(e.lower)
	}
	d.masker = regexp.MustCompile(`(?i)` + strings.Join(alts, "|"))
	return d, nil
}

// Len is the number of entries.
func (d *Denylist) Len() int { return len(d.entries) }

// Hash is D: the first 16 hex digits of the SHA-256 of the entries,
// lower-cased, sorted, joined by newlines.
func (d *Denylist) Hash() string {
	ls := make([]string, len(d.entries))
	for i, e := range d.entries {
		ls[i] = strings.ToLower(e.raw)
	}
	sort.Strings(ls)
	sum := sha256.Sum256([]byte(strings.Join(ls, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// token names entry n.
func token(n int) string { return fmt.Sprintf("token #%d", n) }

// Mask replaces every denylist value in s with its `token #N` name.
func (d *Denylist) Mask(s string) string {
	if d == nil {
		return s
	}
	out := d.masker.ReplaceAllStringFunc(s, func(m string) string {
		lm := strings.ToLower(m)
		for _, e := range d.entries {
			if e.lower == lm {
				return token(e.n)
			}
		}
		return "[masked]"
	})
	// Case folding in the regexp and strings.ToLower differ on a few runes;
	// anything that still carries a value is withheld whole.
	lo := strings.ToLower(out)
	for _, e := range d.entries {
		if strings.Contains(lo, e.lower) {
			return "[masked]"
		}
	}
	return out
}

// hit is one occurrence of an entry at a byte offset of the lower-cased text.
type hit struct {
	n   int
	off int
}

// find returns every occurrence of every entry in lowered, which must already
// be lower-cased.
func (d *Denylist) find(lowered []byte) []hit {
	var hits []hit
	for _, e := range d.entries {
		pat := []byte(e.lower)
		for start := 0; start <= len(lowered)-len(pat); {
			i := bytes.Index(lowered[start:], pat)
			if i < 0 {
				break
			}
			at := start + i
			if !e.word || wholeWord(lowered, at, at+len(pat)) {
				hits = append(hits, hit{e.n, at})
			}
			start = at + 1
		}
	}
	return hits
}

// matchesIn reports the entries that occur in s.
func (d *Denylist) matchesIn(s string) []int {
	if d == nil {
		return nil
	}
	var ns []int
	seen := map[int]bool{}
	for _, h := range d.find([]byte(strings.ToLower(s))) {
		if !seen[h.n] {
			seen[h.n] = true
			ns = append(ns, h.n)
		}
	}
	return ns
}

func wholeWord(b []byte, i, j int) bool {
	if i > 0 {
		r, _ := utf8.DecodeLastRune(b[:i])
		if isWordRune(r) {
			return false
		}
	}
	if j < len(b) {
		r, _ := utf8.DecodeRune(b[j:])
		if isWordRune(r) {
			return false
		}
	}
	return true
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
