package manifest

import (
	"strings"
	"testing"
)

const base = `
version = 1
mode = "snapshot"

[public]
remote = "git@host.example:alice/demo.git"
author = "Alice Example <alice@host.example>"

[paths]
public   = ["cmd/", "internal/", "go.mod", "README.md", ".woodpecker/"]
internal = ["internal/secret/", "cmd/tool/private.go", "docs/"]
`

func mustParse(t *testing.T, s string) *Manifest {
	t.Helper()
	m, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestClassify(t *testing.T) {
	m := mustParse(t, base)
	cases := []struct {
		path  string
		class Class
		entry string
	}{
		{"cmd/tool/main.go", Public, "cmd/"},
		{"cmd/tool/private.go", Internal, "cmd/tool/private.go"}, // a file entry beats its directory
		{"internal/secret/key.go", Internal, "internal/secret/"}, // most specific directory wins
		{"internal/secretive/x.go", Public, "internal/"},         // segment match, not prefix
		{"cmdx/main.go", Unclassified, ""},                       // "cmd/" does not cover "cmdx/"
		{"cmd", Unclassified, ""},                                // a directory entry does not cover its own name
		{"go.mod", Public, "go.mod"},
		{"go.mod.bak", Unclassified, ""},
		{"sub/go.mod", Unclassified, ""}, // a file entry is rooted
		{"docs/a/b.md", Internal, "docs/"},
		{"NOTES.md", Unclassified, ""},
	}
	for _, c := range cases {
		got := m.Classify(c.path)
		if got.Class != c.class || got.Entry != c.entry {
			t.Errorf("Classify(%q) = %v %q, want %v %q", c.path, got.Class, got.Entry, c.class, c.entry)
		}
	}
}

func TestUnclassifiedReported(t *testing.T) {
	m := mustParse(t, base)
	c := m.ClassifyAll([]string{"cmd/a.go", "NOTES.md", "docs/x", "scripts/run.sh"})
	if strings.Join(c.Unclassified, ",") != "NOTES.md,scripts/run.sh" {
		t.Fatalf("unclassified = %v", c.Unclassified)
	}
	if len(c.Public) != 1 || len(c.Internal) != 1 {
		t.Fatalf("public %v internal %v", c.Public, c.Internal)
	}
}

func TestImplicitInternalSnapshot(t *testing.T) {
	// .woodpecker/ is listed public, and the manifest is not listed at all:
	// in snapshot mode both the manifest and the publish pipeline stay internal.
	m := mustParse(t, strings.Replace(base, `"go.mod",`, `"go.mod", ".pubmirror.toml", ".pubmirror/",`, 1))
	for _, p := range []string{".pubmirror.toml", ".pubmirror/hooks/pre-commit", ".woodpecker/public-mirror.yml"} {
		if got := m.Classify(p); got.Class != Internal || !got.Implicit {
			t.Errorf("Classify(%q) = %+v, want implicit internal", p, got)
		}
	}
	if got := m.Classify(".woodpecker/ci.yml"); got.Class != Public {
		t.Errorf("other pipeline files follow the manifest: %+v", got)
	}
	unlisted := mustParse(t, base)
	if got := unlisted.Classify(File); got.Class != Internal {
		t.Errorf("unlisted manifest in snapshot mode = %+v", got)
	}
}

func TestExactMode(t *testing.T) {
	exact := strings.Replace(base, `mode = "snapshot"`, `mode = "exact"`, 1)
	_, err := Parse([]byte(exact))
	if err == nil || !strings.Contains(err.Error(), "paths.internal must be empty") {
		t.Fatalf("exact with internal entries: err = %v", err)
	}
	ok := strings.Replace(exact, `internal = ["internal/secret/", "cmd/tool/private.go", "docs/"]`, `internal = []`, 1)
	m := mustParse(t, ok)
	// No implicit entries: an unlisted manifest is unclassified, a listed one is public and scanned.
	if got := m.Classify(File); got.Class != Unclassified {
		t.Errorf("exact, unlisted manifest = %+v", got)
	}
	m.Paths.Public = append(m.Paths.Public, File)
	if got := m.Classify(File); got.Class != Public {
		t.Errorf("exact, listed manifest = %+v", got)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"version":          {"version = 1", "version = 2", "version must be 1"},
		"mode":             {`mode = "snapshot"`, `mode = "mirror"`, "mode must be"},
		"author":           {`author = "Alice Example <alice@host.example>"`, `author = "alice"`, "public.author"},
		"unknown key":      {"[paths]", "colour = \"red\"\n[paths]", "unknown keys"},
		"absolute path":    {`"go.mod",`, `"/etc/passwd",`, "relative to the repository root"},
		"dot-dot":          {`"go.mod",`, `"../x",`, "not a clean relative path"},
		"listed twice":     {`"docs/"]`, `"docs/", "cmd/"]`, "already listed"},
		"denylist value":   {"[paths]", "[[allow]]\nrule = \"denylist\"\nmatch = \"secret\"\npath = \"cmd/\"\nreason = \"x\"\n[paths]", "token #N"},
		"unknown rule":     {"[paths]", "[[allow]]\nrule = \"nope\"\nmatch = \"x\"\npath = \"cmd/\"\nreason = \"x\"\n[paths]", "unknown rule"},
		"fixture checksum": {"[paths]", "[[fixture]]\npath = \"a.wav\"\nsha256 = \"abc\"\nprovenance = \"synthetic\"\n[paths]", "sha256"},
	}
	for name, c := range cases {
		src := strings.Replace(base, c.from, c.to, 1)
		if src == base {
			t.Fatalf("%s: replacement did not apply", name)
		}
		_, err := Parse([]byte(src))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

func TestAllowAndFixture(t *testing.T) {
	src := base + `
[[fixture]]
path = "internal/audio/testdata/tone.wav"
sha256 = "` + strings.Repeat("ab", 32) + `"
provenance = "synthetic, a 440 Hz tone"

[[allow]]
rule = "denylist"
match = "token #3"
path = "internal/net/"
reason = "fictional"

[verify]
commands = ["go build ./..."]
`
	m := mustParse(t, src)
	if _, ok := m.Fixture("internal/audio/testdata/tone.wav"); !ok {
		t.Fatal("fixture not found")
	}
	if len(m.Allows) != 1 || m.Verify.Commands[0] != "go build ./..." {
		t.Fatalf("%+v", m)
	}
	if addr, _ := m.AuthorAddress(); addr != "alice@host.example" {
		t.Fatalf("author address %q", addr)
	}
}
