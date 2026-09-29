// Package scan holds pubmirror's leak rules, the denylist and the gitleaks
// adapter. It takes plain inputs and imports nothing from this module.
package scan

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Rule names.
const (
	RuleHomePath   = "home-path"
	RuleIP         = "ip"
	RulePrivateURL = "private-url"
	RuleEmail      = "email"
	RuleToken      = "token"
	RuleDenylist   = "denylist"
	RuleDataFile   = "data-file"
	RuleLink       = "link"
	RuleIdentity   = "identity"
	RuleSize       = "size"
)

// Git file modes the rules care about.
const (
	ModeSymlink = 0o120000
	ModeGitlink = 0o160000
)

// MaxSize is the largest file the size rule lets through.
const MaxSize = 50 << 20

// File is one file of the set under scan.
type File struct {
	Path string
	Mode uint32 // git file mode
	Data []byte // for a symlink, its target
}

// Finding is one thing a rule refused.
type Finding struct {
	Path  string
	Line  int // 0 when the finding is about the file, not a line
	Rule  string
	Match string // masked for the token and denylist rules
}

func (f Finding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d: %s: %s", f.Path, f.Line, f.Rule, f.Match)
	}
	return fmt.Sprintf("%s: %s: %s", f.Path, f.Rule, f.Match)
}

// Commit is the metadata of one commit: its message and identities are
// scanned, and in exact mode its identities must be the public author. An
// annotated tag is judged the same way, its tagger as both identities.
type Commit struct {
	Kind      string // "commit" when empty, or "tag"
	ID        string
	Author    string // "Name <address>"
	Committer string // "Name <address>"
	Message   string
}

// Allow exempts one match of one rule within one path scope. A scope ending
// in `/` covers its subtree; any other scope is one file. For the denylist
// rule the match is `token #N`. A finding about a commit (identity, message)
// has no tree path, so the scope is not consulted for it.
type Allow struct {
	Rule   string
	Match  string
	Path   string
	Reason string
}

// Fixture admits one data file whose bytes hash to SHA256 (hex).
type Fixture struct {
	Path       string
	SHA256     string
	Provenance string
}

// TokenScanner finds credentials by shape. Gitleaks is the implementation.
type TokenScanner interface {
	ScanTokens(files []File) ([]Finding, error)
}

// Config is everything a scan judges against.
type Config struct {
	Denylist *Denylist // required
	Author   string    // the public author, "Name <address>"; its address passes the email rule
	Exact    bool      // exact mode: the identity rule applies
	Allow    []Allow
	Fixtures []Fixture
	Tokens   TokenScanner // required
}

// AllowUse is an allow entry that suppressed at least one finding.
type AllowUse struct {
	Allow Allow
	Count int
}

// Report is the outcome of a scan.
type Report struct {
	Findings []Finding  // what remains after the allow entries
	Allowed  []AllowUse // the allow entries that fired
}

// Scan applies every rule to files and commits. An error means the scan could
// not run and the report must not be read as clean.
func Scan(cfg Config, files []File, commits []Commit) (Report, error) {
	if cfg.Denylist == nil || cfg.Denylist.Len() == 0 {
		return Report{}, ErrNoDenylist
	}
	if cfg.Tokens == nil {
		return Report{}, fmt.Errorf("no token scanner configured")
	}
	authorAddr := strings.ToLower(address(cfg.Author))
	fixtures := map[string]Fixture{}
	for _, fx := range cfg.Fixtures {
		fixtures[fx.Path] = fx
	}

	var raw []Finding
	var tokenInput []File
	for _, f := range files {
		raw = append(raw, textRules(cfg.Denylist, authorAddr, f.Path, []byte(f.Path), false)...)
		raw = append(raw, fileRules(cfg.Denylist, fixtures, f)...)
		if f.Mode == ModeGitlink || f.Mode == ModeSymlink {
			continue
		}
		raw = append(raw, textRules(cfg.Denylist, authorAddr, f.Path, f.Data, true)...)
		tokenInput = append(tokenInput, f)
	}
	for _, c := range commits {
		kind := c.Kind
		if kind == "" {
			kind = "commit"
		}
		where := kind + " " + c.ID
		if cfg.Exact {
			for _, id := range []string{c.Author, c.Committer} {
				if id != "" && !sameIdentity(id, cfg.Author) {
					raw = append(raw, Finding{where, 0, RuleIdentity, id})
				}
			}
		}
		msgPath := where + " message"
		raw = append(raw, textRules(cfg.Denylist, authorAddr, msgPath, []byte(c.Message), true)...)
		tokenInput = append(tokenInput, File{Path: msgPath, Mode: 0o100644, Data: []byte(c.Message)})
	}
	if len(tokenInput) > 0 {
		tf, err := cfg.Tokens.ScanTokens(tokenInput)
		if err != nil {
			return Report{}, err
		}
		raw = append(raw, tf...)
	}

	var rep Report
	used := make([]int, len(cfg.Allow))
	seen := map[Finding]bool{}
	for _, f := range raw {
		if f.Rule != RuleDenylist && f.Rule != RuleToken {
			f.Match = cfg.Denylist.Mask(f.Match)
		}
		f.Path = cfg.Denylist.Mask(f.Path)
		if seen[f] {
			continue
		}
		seen[f] = true
		if i := allowFor(cfg.Allow, f); i >= 0 {
			used[i]++
			continue
		}
		rep.Findings = append(rep.Findings, f)
	}
	for i, n := range used {
		if n > 0 {
			rep.Allowed = append(rep.Allowed, AllowUse{cfg.Allow[i], n})
		}
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Match < b.Match
	})
	return rep, nil
}

// allowFor returns the index of the first allow entry that exempts f, or -1.
// A data file is admitted by a [[fixture]] entry only, never by an allow.
func allowFor(allows []Allow, f Finding) int {
	if f.Rule == RuleDataFile {
		return -1
	}
	for i, a := range allows {
		if a.Rule != f.Rule || !strings.EqualFold(a.Match, f.Match) {
			continue
		}
		if strings.HasPrefix(f.Path, "commit ") || InScope(a.Path, f.Path) {
			return i
		}
	}
	return -1
}

// InScope reports whether path lies in scope: a scope ending in `/` covers
// its subtree by path segment; any other scope is exactly one file.
func InScope(scope, path string) bool {
	if scope == "" {
		return false
	}
	if strings.HasSuffix(scope, "/") {
		return strings.HasPrefix(path, scope)
	}
	return path == scope
}

// address extracts the address from "Name <address>", or returns s trimmed.
func address(s string) string {
	if i := strings.LastIndexByte(s, '<'); i >= 0 {
		if j := strings.IndexByte(s[i:], '>'); j > 0 {
			return strings.TrimSpace(s[i+1 : i+j])
		}
	}
	return strings.TrimSpace(s)
}

func sameIdentity(a, b string) bool {
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	name := func(s string) string {
		if i := strings.LastIndexByte(s, '<'); i >= 0 {
			return norm(s[:i])
		}
		return ""
	}
	return name(a) == name(b) && strings.EqualFold(address(a), address(b))
}

// lineIndex maps byte offsets to 1-based line numbers.
type lineIndex []int

func newLineIndex(b []byte) lineIndex {
	var nl lineIndex
	for i := 0; ; {
		j := bytes.IndexByte(b[i:], '\n')
		if j < 0 {
			return nl
		}
		nl = append(nl, i+j)
		i += j + 1
	}
}

func (li lineIndex) line(off int) int {
	return sort.SearchInts(li, off) + 1
}
