package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/pubmirror/internal/gittest"
)

// The fictional private value every check test plants.
const planted = "private-host.example"

func withDenylist(t *testing.T, text string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "denylist.txt")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUBMIRROR_DENYLIST", p)
}

func runCheck(t *testing.T, cwd string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := check(args, cwd, &out, &errb)
	return rc, out.String(), errb.String()
}

func plainDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, s := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCheckDenylistRequired(t *testing.T) {
	dir := plainDir(t, map[string]string{"a.go": "package a\n"})
	t.Setenv("PUBMIRROR_DENYLIST", filepath.Join(t.TempDir(), "absent.txt"))
	if rc, _, e := runCheck(t, dir, "--dir", "."); rc != exitCannot || !strings.Contains(e, "denylist missing") {
		t.Fatalf("absent denylist: rc %d, %q", rc, e)
	}
	withDenylist(t, "# nothing but a comment\n\n")
	if rc, _, e := runCheck(t, dir, "--dir", "."); rc != exitCannot || !strings.Contains(e, "denylist missing or empty") {
		t.Fatalf("empty denylist: rc %d, %q", rc, e)
	}
}

func TestCheckGitleaksCannotRun(t *testing.T) {
	withDenylist(t, planted+"\n")
	dir := plainDir(t, map[string]string{"a.go": "package a\n"})

	t.Setenv("PUBMIRROR_GITLEAKS", filepath.Join(t.TempDir(), "no-gitleaks"))
	if rc, _, e := runCheck(t, dir, "--dir", "."); rc != exitCannot || !strings.Contains(e, "not found") {
		t.Fatalf("missing gitleaks: rc %d, %q", rc, e)
	}

	crash := filepath.Join(t.TempDir(), "gitleaks")
	os.WriteFile(crash, []byte("#!/bin/sh\necho 'panic: runtime error' >&2\nexit 1\n"), 0o700)
	t.Setenv("PUBMIRROR_GITLEAKS", crash)
	if rc, _, e := runCheck(t, dir, "--dir", "."); rc != exitCannot || !strings.Contains(e, "no report written: panic: runtime error") {
		t.Fatalf("crashing gitleaks: rc %d, %q", rc, e)
	}
}

func needGitleaks(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}
}

func TestCheckDirNamesTokenNeverValue(t *testing.T) {
	needGitleaks(t)
	withDenylist(t, "# fictional\nunrelated-value\n"+planted+"\n")
	dir := plainDir(t, map[string]string{
		"src/a.go":                "package a\n\n// served from " + strings.ToUpper(planted) + "\n",
		"src/testdata/golden.txt": "a sentence written for the test\n",
		"docs/b.md":               "clean\n",
	})
	rc, out, _ := runCheck(t, dir, "--dir", dir, "src")
	if rc != exitFindings {
		t.Fatalf("rc %d, %s", rc, out)
	}
	for _, want := range []string{
		"src/a.go:3: denylist: token #2",
		"src/testdata/golden.txt: data-file: under testdata/, no fixture entry",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Fatalf("want %q in:\n%s", want, out)
		}
	}
	if strings.Contains(strings.ToLower(out), planted) || strings.Contains(out, "docs/b.md") {
		t.Fatalf("value or out-of-scope path in output:\n%s", out)
	}
}

func TestCheckHistoryAddedThenRemoved(t *testing.T) {
	needGitleaks(t)
	withDenylist(t, planted+"\n")
	r := gittest.Init(t)
	gittest.Commit(t, r, "start", map[string]string{
		".pubmirror.toml": gittest.Manifest("exact", "https://github.example/alice/r.git"),
		"src/a.go":        "package a\n",
	})
	added := gittest.Commit(t, r, "add", map[string]string{"src/a.go": "package a\n\nvar host = \"" + planted + "\"\n"})
	gittest.Commit(t, r, "remove", map[string]string{"src/a.go": "package a\n"})

	if rc, out, e := runCheck(t, r.Dir, "--commit", "HEAD"); rc != exitClean {
		t.Fatalf("the tip is clean: rc %d\n%s%s", rc, out, e)
	}
	rc, out, e := runCheck(t, r.Dir, "--history", "HEAD")
	if rc != exitFindings {
		t.Fatalf("history: rc %d\n%s%s", rc, out, e)
	}
	if want := short(added) + ":src/a.go:3: denylist: token #1\n"; !strings.Contains(out, want) {
		t.Fatalf("want %q in:\n%s", want, out)
	}
}
