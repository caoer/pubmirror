package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const author = "Alice Example <alice@host.example>"

// fakeTokens reports a token finding on every line holding "FAKE-TOKEN".
type fakeTokens struct{}

func (fakeTokens) ScanTokens(files []File) ([]Finding, error) {
	var out []Finding
	for _, f := range files {
		for i, l := range strings.Split(string(f.Data), "\n") {
			if strings.Contains(l, "FAKE-TOKEN") {
				out = append(out, Finding{f.Path, i + 1, RuleToken, "fake-rule"})
			}
		}
	}
	return out, nil
}

func denylist(t *testing.T, text string) *Denylist {
	t.Helper()
	d, err := ParseDenylist([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func cfg(t *testing.T) Config {
	return Config{
		Denylist: denylist(t, "# private values\nsecret-host\nword:bob\n"),
		Author:   author,
		Tokens:   fakeTokens{},
	}
}

func text(p, s string) File { return File{Path: p, Mode: 0o100644, Data: []byte(s)} }

func run(t *testing.T, c Config, files []File, commits ...Commit) Report {
	t.Helper()
	rep, err := Scan(c, files, commits)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Each rule: a planted value fires, and the same value under an [[allow]]
// entry (a [[fixture]] entry for data-file) does not.
func TestRules(t *testing.T) {
	big := make([]byte, MaxSize+1)
	for i := range big {
		big[i] = 'a'
	}
	cases := []struct {
		name   string
		files  []File
		exact  bool
		commit *Commit
		want   Finding
		allow  []Allow
		fix    []Fixture
	}{
		{name: "home-path", files: []File{text("docs/a.md", "see /Users/alice/src\n")},
			want:  Finding{"docs/a.md", 1, RuleHomePath, "/Users/alice"},
			allow: []Allow{{RuleHomePath, "/Users/alice", "docs/", "path shape under test"}}},
		{name: "home-path windows", files: []File{text("a.go", `x := "C:\\Users\\alice\\x"`+"\n")},
			want:  Finding{"a.go", 1, RuleHomePath, `C:\\Users\\alice`},
			allow: []Allow{{RuleHomePath, `C:\\Users\\alice`, "a.go", "test"}}},
		{name: "ipv4", files: []File{text("n.go", "a\naddr := \"10.0.0.5:80\"\n")},
			want:  Finding{"n.go", 2, RuleIP, "10.0.0.5"},
			allow: []Allow{{RuleIP, "10.0.0.5", "n.go", "test address"}}},
		{name: "ipv6", files: []File{text("n.go", "peer fd12:3456::7 up\n")},
			want:  Finding{"n.go", 1, RuleIP, "fd12:3456::7"},
			allow: []Allow{{RuleIP, "fd12:3456::7", "n.go", "test"}}},
		{name: "private-url ssh", files: []File{text("README.md", "clone ssh://git@host.example:2222/alice/r.git\n")},
			want:  Finding{"README.md", 1, RulePrivateURL, "ssh://git@host.example:2222/alice/r.git"},
			allow: []Allow{{RulePrivateURL, "ssh://git@host.example:2222/alice/r.git", "README.md", "test"}}},
		{name: "private-url denylisted host", files: []File{text("a.md", "at https://secret-host.example/x now\n")},
			want:  Finding{"a.md", 1, RulePrivateURL, "https://token #1.example/x"},
			allow: []Allow{{RulePrivateURL, "https://token #1.example/x", "a.md", "test"}, {RuleDenylist, "token #1", "a.md", "test"}}},
		{name: "email", files: []File{text("a.md", "mail carol@host.example or alice@host.example\n")},
			want:  Finding{"a.md", 1, RuleEmail, "carol@host.example"},
			allow: []Allow{{RuleEmail, "carol@host.example", "a.md", "test"}}},
		{name: "token", files: []File{text("k.go", "x\ny FAKE-TOKEN\n")},
			want:  Finding{"k.go", 2, RuleToken, "fake-rule"},
			allow: []Allow{{RuleToken, "fake-rule", "k.go", "test"}}},
		{name: "denylist", files: []File{text("a.go", "// runs on Secret-Host\n")},
			want:  Finding{"a.go", 1, RuleDenylist, "token #1"},
			allow: []Allow{{RuleDenylist, "token #1", "a.go", "test"}}},
		{name: "denylist word", files: []File{text("a.txt", "bobby\nask bob.\n")},
			want:  Finding{"a.txt", 2, RuleDenylist, "token #2"},
			allow: []Allow{{RuleDenylist, "token #2", "a.txt", "test"}}},
		{name: "data-file testdata txt", files: []File{text("post/testdata/filler/01.txt", "a sentence\n")},
			want: Finding{"post/testdata/filler/01.txt", 0, RuleDataFile, "under testdata/, no fixture entry"},
			fix:  []Fixture{{"post/testdata/filler/01.txt", sha([]byte("a sentence\n")), "written for the test"}}},
		{name: "data-file extension", files: []File{{"a/take.wav", 0o100644, []byte("RIFF")}},
			want: Finding{"a/take.wav", 0, RuleDataFile, "extension .wav, no fixture entry"},
			fix:  []Fixture{{"a/take.wav", sha([]byte("RIFF")), "synthetic"}}},
		{name: "data-file binary", files: []File{{"a/blob", 0o100644, []byte("x\x00y")}},
			want: Finding{"a/blob", 0, RuleDataFile, "binary, no fixture entry"},
			fix:  []Fixture{{"a/blob", sha([]byte("x\x00y")), "synthetic"}}},
		{name: "data-file annex", files: []File{{"m/w.gguf", ModeSymlink, []byte("../.git/annex/objects/ab/cd/K/K")}},
			want: Finding{"m/w.gguf", 0, RuleDataFile, "extension .gguf, symlink, git-annex pointer, no fixture entry"}},
		{name: "link", files: []File{{"a/l", ModeSymlink, []byte("../../outside")}},
			want:  Finding{"a/l", 0, RuleLink, "../../outside"},
			allow: []Allow{{RuleLink, "../../outside", "a/l", "test"}},
			fix:   []Fixture{{"a/l", sha([]byte("../../outside")), "test"}}},
		{name: "gitmodules", files: []File{text(".gitmodules", "[submodule \"x\"]\n\turl = https://secret-host.example/x.git\n")},
			want:  Finding{".gitmodules", 2, RuleLink, "https://token #1.example/x.git"},
			allow: []Allow{{RuleLink, "https://token #1.example/x.git", ".gitmodules", "t"}, {RulePrivateURL, "https://token #1.example/x.git", ".gitmodules", "t"}, {RuleDenylist, "token #1", ".gitmodules", "t"}}},
		{name: "identity", exact: true, commit: &Commit{ID: "c1", Author: "Carol <carol@host.example>", Committer: author, Message: "m\n"},
			want:  Finding{"commit c1", 0, RuleIdentity, "Carol <carol@host.example>"},
			allow: []Allow{{RuleIdentity, "Carol <carol@host.example>", "", "test"}}},
		{name: "size", files: []File{{"big.txt", 0o100644, big}},
			want:  Finding{"big.txt", 0, RuleSize, "52428801 bytes"},
			allow: []Allow{{RuleSize, "52428801 bytes", "big.txt", "test"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg(t)
			c.Exact = tc.exact
			var commits []Commit
			if tc.commit != nil {
				commits = []Commit{*tc.commit}
			}
			rep := run(t, c, tc.files, commits...)
			if !has(rep.Findings, tc.want) {
				t.Fatalf("planted value did not fire: want %v, got %v", tc.want, rep.Findings)
			}
			c.Allow, c.Fixtures = tc.allow, tc.fix
			rep = run(t, c, tc.files, commits...)
			if tc.allow == nil && tc.fix == nil {
				return
			}
			if len(rep.Findings) != 0 {
				t.Fatalf("exempted value still fired: %v", rep.Findings)
			}
			if tc.allow != nil && len(rep.Allowed) == 0 {
				t.Fatalf("report lists no allow entry that fired")
			}
		})
	}
}

func has(fs []Finding, want Finding) bool {
	for _, f := range fs {
		if f == want {
			return true
		}
	}
	return false
}

func TestPublicSafeValuesPass(t *testing.T) {
	c := cfg(t)
	rep := run(t, c, []File{text("a.go", strings.Join([]string{
		"127.0.0.1 0.0.0.0 192.0.2.7 198.51.100.1 203.0.113.9",
		"::1 2001:db8::5 3fff::1",
		"version 1.2.3.4.5 and v10.0.0.5",
		"s = a[1::2]",
		"at 12:30:45",
		"https://example.com/home/alice/page",
		"logo@2x.png",
		"by alice@host.example",
		"bobby",
	}, "\n")+"\n")})
	if len(rep.Findings) != 0 {
		t.Fatalf("public-safe values fired: %v", rep.Findings)
	}
}

func TestAllowScope(t *testing.T) {
	c := cfg(t)
	c.Allow = []Allow{{RuleIP, "10.0.0.5", "a/", "test"}}
	rep := run(t, c, []File{text("a/x.go", "10.0.0.5\n"), text("ab/x.go", "10.0.0.5\n")})
	if len(rep.Findings) != 1 || rep.Findings[0].Path != "ab/x.go" {
		t.Fatalf("scope a/ must cover a/x.go only: %v", rep.Findings)
	}
}

func TestFixtureShaMismatch(t *testing.T) {
	c := cfg(t)
	c.Fixtures = []Fixture{{"testdata/x.txt", sha([]byte("old")), "t"}}
	rep := run(t, c, []File{text("testdata/x.txt", "new")})
	if !has(rep.Findings, Finding{"testdata/x.txt", 0, RuleDataFile, "sha256 differs from its fixture entry"}) {
		t.Fatalf("changed fixture bytes must fire: %v", rep.Findings)
	}
}

func TestPathIsScanned(t *testing.T) {
	rep := run(t, cfg(t), []File{text("notes/secret-host.md", "x\n")})
	if !has(rep.Findings, Finding{"notes/token #1.md", 0, RuleDenylist, "token #1"}) {
		t.Fatalf("a value in a path must fire, masked: %v", rep.Findings)
	}
}

func TestCommitMessageScanned(t *testing.T) {
	rep := run(t, cfg(t), nil, Commit{ID: "c2", Author: author, Committer: author, Message: "deploy to secret-host\n\nFAKE-TOKEN\n"})
	want := []Finding{{"commit c2 message", 1, RuleDenylist, "token #1"}, {"commit c2 message", 3, RuleToken, "fake-rule"}}
	for _, w := range want {
		if !has(rep.Findings, w) {
			t.Fatalf("want %v in %v", w, rep.Findings)
		}
	}
}

// No output carries a denylist value: every rule's match is masked.
func TestNoValueInAnyFinding(t *testing.T) {
	c := cfg(t)
	c.Exact = true
	rep := run(t, c, []File{
		text("a.md", "ssh://secret-host/x /Users/secret-host SECRET-HOST secret-host@host.example\n"),
		{"l", ModeSymlink, []byte("/srv/secret-host")},
	}, Commit{ID: "c3", Author: "Secret-Host <x@host.example>", Committer: author, Message: "m"})
	if len(rep.Findings) < 5 {
		t.Fatalf("expected findings from several rules, got %v", rep.Findings)
	}
	for _, f := range rep.Findings {
		if strings.Contains(strings.ToLower(f.String()), "secret-host") {
			t.Fatalf("value leaked into %q", f)
		}
	}
}

func TestDenylistLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadDenylist(filepath.Join(dir, "absent.txt")); !errors.Is(err, ErrNoDenylist) {
		t.Fatalf("absent: %v", err)
	}
	empty := filepath.Join(dir, "empty.txt")
	os.WriteFile(empty, []byte("# only a comment\n\n   \n"), 0o600)
	if _, err := LoadDenylist(empty); !errors.Is(err, ErrNoDenylist) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := Scan(Config{Tokens: fakeTokens{}}, nil, nil); !errors.Is(err, ErrNoDenylist) {
		t.Fatalf("scan without denylist: %v", err)
	}
}

func TestDenylistHash(t *testing.T) {
	a := denylist(t, "Beta\nalpha # a comment\n")
	b := denylist(t, "# header\nALPHA\n\nbeta\n")
	sum := sha256.Sum256([]byte("alpha\nbeta"))
	want := hex.EncodeToString(sum[:])[:16]
	if a.Hash() != want || b.Hash() != want {
		t.Fatalf("hash %s %s, want %s", a.Hash(), b.Hash(), want)
	}
}
