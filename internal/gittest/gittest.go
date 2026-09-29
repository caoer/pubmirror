// Package gittest builds scratch repositories for tests. Every value in them is
// fictional.
package gittest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/pubmirror/internal/gitobj"
)

// Author is the fictional public author of test manifests.
const Author = "Alice Example <alice@host.example>"

// Env isolates git from the user's configuration and names a fictional author.
var Env = []string{
	"GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
	"GIT_AUTHOR_NAME=Dev Example", "GIT_AUTHOR_EMAIL=dev@host.example",
	"GIT_COMMITTER_NAME=Dev Example", "GIT_COMMITTER_EMAIL=dev@host.example",
	"GIT_TERMINAL_PROMPT=0",
}

// Init makes a working repository on branch main.
func Init(t *testing.T) *gitobj.Repo {
	t.Helper()
	r := &gitobj.Repo{Dir: t.TempDir(), Env: Env}
	Git(t, r, "init", "-q", "-b", "main")
	return r
}

// Bare makes a bare repository and returns its path.
func Bare(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	c := exec.Command("git", "init", "-q", "--bare", "-b", "main", dir)
	c.Env = append(os.Environ(), Env...)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v %s", err, out)
	}
	return dir
}

// Git runs git in r and returns its trimmed output, failing the test on error.
func Git(t *testing.T, r *gitobj.Repo, args ...string) string {
	t.Helper()
	out, err := r.Run(args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// Write writes files (path → content) into r's working tree. An empty content
// removes the file.
func Write(t *testing.T, r *gitobj.Repo, files map[string]string) {
	t.Helper()
	for name, data := range files {
		p := filepath.Join(r.Dir, filepath.FromSlash(name))
		if data == "" {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Commit writes files, commits every change and returns the new commit.
func Commit(t *testing.T, r *gitobj.Repo, msg string, files map[string]string) string {
	t.Helper()
	Write(t, r, files)
	Git(t, r, "add", "-A")
	Git(t, r, "commit", "-q", "--allow-empty", "-m", msg)
	return Git(t, r, "rev-parse", "HEAD")
}

// Manifest returns a manifest for mode with the given public remote.
func Manifest(mode, remote string) string {
	internal := `["notes/"]`
	if mode == "exact" {
		internal = `[]`
	}
	return `version = 1
mode = "` + mode + `"

[public]
remote = "` + remote + `"
author = "` + Author + `"

[paths]
public   = ["src/", "README.md"` + map[bool]string{true: `, ".pubmirror.toml"`}[mode == "exact"] + `]
internal = ` + internal + `
`
}
