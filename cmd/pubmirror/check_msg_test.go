package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/pubmirror/internal/gittest"
)

func TestCheckMsg(t *testing.T) {
	needGitleaks(t)
	withDenylist(t, planted+"\n")
	for _, kv := range gittest.Env {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	name, addr, _ := strings.Cut(strings.TrimSuffix(gittest.Author, ">"), " <")

	r := gittest.Init(t)
	msg := filepath.Join(t.TempDir(), "COMMIT_EDITMSG")
	run := func(text string) (int, string) {
		t.Helper()
		if err := os.WriteFile(msg, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		rc := checkMsg([]string{msg}, r.Dir, &out, &errb)
		return rc, out.String() + errb.String()
	}

	if rc, out := run("anything\n"); rc != exitCannot || !strings.Contains(out, "no .pubmirror.toml in the index") {
		t.Fatalf("no manifest: rc %d, %s", rc, out)
	}

	gittest.Write(t, r, map[string]string{".pubmirror.toml": gittest.Manifest("snapshot", "git@host.example:alice/repo.git")})
	gittest.Git(t, r, "add", ".pubmirror.toml")
	if rc, out := run("mentions " + planted + "\n"); rc != exitClean {
		t.Fatalf("snapshot mode publishes no canonical message: rc %d, %s", rc, out)
	}

	gittest.Write(t, r, map[string]string{".pubmirror.toml": gittest.Manifest("exact", "git@host.example:alice/repo.git")})
	gittest.Git(t, r, "add", ".pubmirror.toml")

	// The author and committer git would record are the test environment's
	// Dev Example, not the manifest's author.
	rc, out := run("a clean message\n")
	if rc != exitFindings || strings.Count(out, "identity") < 2 {
		t.Fatalf("foreign identity: rc %d, %s", rc, out)
	}

	for _, k := range []string{"GIT_AUTHOR", "GIT_COMMITTER"} {
		t.Setenv(k+"_NAME", name)
		t.Setenv(k+"_EMAIL", addr)
	}
	if rc, out := run("a clean message\n# " + planted + " in a comment git strips\n"); rc != exitClean {
		t.Fatalf("clean: rc %d, %s", rc, out)
	}
	rc, out = run("fix the " + planted + " path\n")
	if rc != exitFindings || !strings.Contains(out, "token #1") || strings.Contains(out, planted) {
		t.Fatalf("denylist hit: rc %d, %s", rc, out)
	}
}
