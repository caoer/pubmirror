// Package manifest parses and validates .pubmirror.toml and classifies paths
// as public, internal or unclassified.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// File is the manifest's path at the repository root.
const File = ".pubmirror.toml"

// ImplicitInternal lists the paths that are internal in snapshot mode without
// being listed: the manifest, the hook shim directory and the publish pipeline.
// An entry ending in "/" covers its subtree.
var ImplicitInternal = []string{File, ".pubmirror/", ".woodpecker/public-mirror.yml"}

// Rules names the scanner rules an [[allow]] entry may name.
var Rules = []string{"home-path", "ip", "private-url", "email", "token", "denylist", "data-file", "link", "identity", "size"}

const (
	ModeSnapshot = "snapshot"
	ModeExact    = "exact"
)

type Manifest struct {
	Version  int        `toml:"version"`
	Mode     string     `toml:"mode"`
	Public   PublicRepo `toml:"public"`
	Paths    Paths      `toml:"paths"`
	Fixtures []Fixture  `toml:"fixture"`
	Allows   []Allow    `toml:"allow"`
	Verify   Verify     `toml:"verify"`
}

type PublicRepo struct {
	Remote string `toml:"remote"`
	Author string `toml:"author"`
}

type Paths struct {
	Public   []string `toml:"public"`
	Internal []string `toml:"internal"`
}

type Fixture struct {
	Path       string `toml:"path"`
	SHA256     string `toml:"sha256"`
	Provenance string `toml:"provenance"`
}

type Allow struct {
	Rule   string `toml:"rule"`
	Match  string `toml:"match"`
	Path   string `toml:"path"`
	Reason string `toml:"reason"`
}

type Verify struct {
	Commands []string `toml:"commands"`
}

// Parse decodes and validates a manifest. Unknown keys are an error.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("manifest: unknown keys: %s", strings.Join(keys, ", "))
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return &m, nil
}

// Load reads and parses a manifest file.
func Load(file string) (*Manifest, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return Parse(data)
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (m *Manifest) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if m.Version != 1 {
		bad("version must be 1, got %d", m.Version)
	}
	if m.Mode != ModeSnapshot && m.Mode != ModeExact {
		bad("mode must be %q or %q, got %q", ModeSnapshot, ModeExact, m.Mode)
	}
	if m.Public.Remote == "" {
		bad("public.remote is required")
	}
	if _, err := m.AuthorAddress(); err != nil {
		bad("public.author: %v", err)
	}
	if len(m.Paths.Public) == 0 {
		bad("paths.public is empty")
	}
	if m.Mode == ModeExact && len(m.Paths.Internal) > 0 {
		bad("exact mode publishes every commit as it is: paths.internal must be empty, has %d entries", len(m.Paths.Internal))
	}
	seen := map[string]string{}
	for list, entries := range map[string][]string{"public": m.Paths.Public, "internal": m.Paths.Internal} {
		for _, e := range entries {
			if err := checkEntry(e); err != nil {
				bad("paths.%s: %v", list, err)
				continue
			}
			if prev, dup := seen[e]; dup {
				bad("paths.%s: %q is already listed in paths.%s", list, e, prev)
			}
			seen[e] = list
		}
	}
	for i, f := range m.Fixtures {
		if err := checkFile(f.Path); err != nil {
			bad("fixture #%d: path: %v", i+1, err)
		}
		if !hex64.MatchString(f.SHA256) {
			bad("fixture #%d (%s): sha256 must be 64 lower-case hex digits", i+1, f.Path)
		}
		if strings.TrimSpace(f.Provenance) == "" {
			bad("fixture #%d (%s): provenance is required", i+1, f.Path)
		}
	}
	for i, a := range m.Allows {
		if !slices.Contains(Rules, a.Rule) {
			bad("allow #%d: unknown rule %q", i+1, a.Rule)
		}
		if a.Match == "" {
			bad("allow #%d: match is required", i+1)
		}
		if a.Rule == "denylist" && !denyRef.MatchString(a.Match) {
			bad("allow #%d: a denylist match is written as \"token #N\", never the value", i+1)
		}
		if err := checkEntry(a.Path); err != nil {
			bad("allow #%d: path: %v", i+1, err)
		}
		if strings.TrimSpace(a.Reason) == "" {
			bad("allow #%d: reason is required", i+1)
		}
	}
	return errors.Join(errs...)
}

var denyRef = regexp.MustCompile(`^token #[1-9][0-9]*$`)

// AuthorAddress returns the e-mail address of the public author.
func (m *Manifest) AuthorAddress() (string, error) {
	_, addr, err := m.AuthorParts()
	return addr, err
}

// AuthorParts splits the public author "Name <address>".
func (m *Manifest) AuthorParts() (name, addr string, err error) {
	if m.Public.Author == "" {
		return "", "", errors.New("required, as \"Name <address>\"")
	}
	a, err := mail.ParseAddress(m.Public.Author)
	if err != nil || a.Name == "" {
		return "", "", fmt.Errorf("%q is not \"Name <address>\"", m.Public.Author)
	}
	return a.Name, a.Address, nil
}

// checkEntry validates a path entry: a file, or a directory ending in "/".
func checkEntry(e string) error {
	return checkFile(strings.TrimSuffix(e, "/"))
}

func checkFile(p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case strings.HasPrefix(p, "/"):
		return fmt.Errorf("%q: paths are relative to the repository root", p)
	case path.Clean(p) != p || strings.HasPrefix(p, "../") || p == "..":
		return fmt.Errorf("%q: not a clean relative path", p)
	}
	return nil
}

// Class is the classification of a path.
type Class int

const (
	Unclassified Class = iota
	Public
	Internal
)

func (c Class) String() string {
	switch c {
	case Public:
		return "public"
	case Internal:
		return "internal"
	}
	return "unclassified"
}

// Match is the classification of one path and the entry that decided it.
// Entry is empty for an unclassified path.
type Match struct {
	Class    Class
	Entry    string
	Implicit bool // decided by ImplicitInternal
}

// Classify decides one path. In snapshot mode ImplicitInternal wins over any
// listed entry; otherwise the most specific matching entry wins.
func (m *Manifest) Classify(p string) Match {
	if m.Mode == ModeSnapshot {
		for _, e := range ImplicitInternal {
			if covers(e, p) {
				return Match{Class: Internal, Entry: e, Implicit: true}
			}
		}
	}
	best, bestScore := Match{}, -1
	try := func(entries []string, c Class) {
		for _, e := range entries {
			if s := specificity(e, p); s > bestScore {
				best, bestScore = Match{Class: c, Entry: e}, s
			}
		}
	}
	try(m.Paths.Public, Public)
	try(m.Paths.Internal, Internal)
	return best
}

// covers reports whether entry e matches path p by segment.
func covers(e, p string) bool {
	if dir, ok := strings.CutSuffix(e, "/"); ok {
		return strings.HasPrefix(p, dir+"/")
	}
	return p == e
}

// specificity is -1 when e does not cover p; otherwise the number of segments
// of e, with a file entry counting above any directory that contains it.
func specificity(e string, p string) int {
	if !covers(e, p) {
		return -1
	}
	segs := strings.Count(strings.TrimSuffix(e, "/"), "/") + 1
	if !strings.HasSuffix(e, "/") {
		return 2*segs + 1
	}
	return 2 * segs
}

// Fixture returns the [[fixture]] entry for a path, if any.
func (m *Manifest) Fixture(p string) (Fixture, bool) {
	for _, f := range m.Fixtures {
		if f.Path == p {
			return f, true
		}
	}
	return Fixture{}, false
}

// Classification groups paths by class.
type Classification struct {
	Public, Internal, Unclassified []string
}

// ClassifyAll classifies a list of paths, keeping their order within each class.
func (m *Manifest) ClassifyAll(paths []string) Classification {
	var c Classification
	for _, p := range paths {
		switch m.Classify(p).Class {
		case Public:
			c.Public = append(c.Public, p)
		case Internal:
			c.Internal = append(c.Internal, p)
		default:
			c.Unclassified = append(c.Unclassified, p)
		}
	}
	return c
}
