package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSameRemote(t *testing.T) {
	same := [][2]string{
		{"git@github.com:alice/repo.git", "ssh://git@github.com/alice/repo"},
		{"git@github.com:alice/repo.git", "https://github.com/Alice/Repo.git/"},
		{"git@github.com:alice/repo.git", "ssh://git@github.com:22/alice/repo.git"},
		{"/srv/public.git", "/srv/public.git/"},
	}
	for _, p := range same {
		if !sameRemote(p[0], p[1]) {
			t.Errorf("%s and %s should match", p[0], p[1])
		}
	}
	diff := [][2]string{
		{"git@github.com:alice/repo.git", "git@github.com:alice/repo-private.git"},
		{"git@github.com:alice/repo.git", "git@host.example:alice/repo.git"},
		{"/srv/public.git", "/srv/other.git"},
		{"", ""},
	}
	for _, p := range diff {
		if sameRemote(p[0], p[1]) {
			t.Errorf("%s and %s should differ", p[0], p[1])
		}
	}
}

func TestGuardPush(t *testing.T) {
	dir := t.TempDir()
	public := filepath.Join(dir, "public.git")
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=alice", "GIT_AUTHOR_EMAIL=alice@host.example",
			"GIT_COMMITTER_NAME=alice", "GIT_COMMITTER_EMAIL=alice@host.example")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	run("commit", "-q", "--allow-empty", "-m", "before adoption")
	run("branch", "old")
	m := "version = 1\nmode = \"snapshot\"\n[public]\nremote = \"" + public + "\"\nauthor = \"Alice <alice@host.example>\"\n[paths]\npublic = [\"a.txt\"]\n"
	if err := os.WriteFile(filepath.Join(dir, ".pubmirror.toml"), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "adopt")
	tip := run("rev-parse", "HEAD")
	line := "refs/heads/main " + tip + " refs/heads/main " + zeroOID + "\n"

	var checked []string
	saved, had := commands["check"]
	commands["check"] = command{"stub", func(args []string) int { checked = append(checked, strings.Join(args, " ")); return exitClean }}
	defer func() {
		if had {
			commands["check"] = saved
		} else {
			delete(commands, "check")
		}
	}()

	if rc := guardPush([]string{"public", public + "/"}, strings.NewReader(line), dir); rc != exitFindings {
		t.Fatalf("push to the public remote: rc = %d, want 1", rc)
	}
	del := ":" + " " + zeroOID + " refs/heads/main " + tip + "\n"
	if rc := guardPush([]string{"public", public}, strings.NewReader(del), dir); rc != exitFindings {
		t.Fatalf("deletion on the public remote: rc = %d, want 1", rc)
	}
	if len(checked) != 0 {
		t.Fatalf("check ran on a refused push: %v", checked)
	}

	if rc := guardPush([]string{"origin", "ssh://git@host.example/alice/repo.git"}, strings.NewReader(line), dir); rc != exitClean {
		t.Fatalf("push to canonical: rc = %d, want 0", rc)
	}
	if len(checked) != 1 || checked[0] != "--commit "+tip {
		t.Fatalf("check calls = %v", checked)
	}

	// From a branch that predates adoption: neither HEAD nor the pushed tip
	// has a manifest; main's names the public remote.
	run("checkout", "-q", "old")
	oldTip := run("rev-parse", "HEAD")
	oldLine := "refs/heads/old " + oldTip + " refs/heads/old " + zeroOID + "\n"
	if rc := guardPush([]string{"public", public}, strings.NewReader(oldLine), dir); rc != exitFindings {
		t.Fatalf("push from a pre-adoption branch to the public remote: rc = %d, want 1", rc)
	}
	run("checkout", "-q", "main")

	commands["check"] = command{"stub", func([]string) int { return exitCannot }}
	if rc := guardPush([]string{"origin", "ssh://git@host.example/alice/repo.git"}, strings.NewReader(line), dir); rc != exitCannot {
		t.Fatalf("check could not run: rc = %d, want 2", rc)
	}
}
