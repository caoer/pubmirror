// Package hooks writes pubmirror's git hook shims and points git at them.
//
// The shims live under the git common directory, in pubmirror/hooks, and
// core.hooksPath is set to that absolute path. Every worktree of the clone shares
// the common directory, so every worktree runs the same shims, whatever branch
// it has checked out; a relative core.hooksPath would resolve inside each
// worktree and silently run nothing where the directory is missing.
//
// Setting core.hooksPath stops git from reading the directory it used before
// (by default .git/hooks). Each hook found there gets a shim that runs it first,
// so hooks another tool installed, such as git-annex's, keep running.
package hooks

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Guarded are the hooks whose shims also run pubmirror.
var Guarded = []string{"pre-commit", "commit-msg", "pre-push"}

// guardArgs is the pubmirror command each guarded hook runs. The hook's own
// arguments follow.
var guardArgs = map[string]string{
	"pre-commit": "check --staged",
	"commit-msg": "check-msg",
	"pre-push":   "guard-push",
}

// Dir is the shim directory, relative to the git common directory.
const Dir = "pubmirror/hooks"

// chainFile records, under the git common directory, the hook directory the
// shims chain to, so that a second install does not chain the shims to
// themselves.
const chainFile = "pubmirror/chain"

// Result says what Install did.
type Result struct {
	HooksPath string   // absolute path now in core.hooksPath
	Chained   string   // directory whose hooks the shims run first
	Shims     []string // hook names written
	Worktrees []WorktreeCheck
}

// WorktreeCheck is the core.hooksPath a worktree resolves after install.
type WorktreeCheck struct {
	Path      string
	HooksPath string
	OK        bool
}

// Install writes the shims for the repository containing dir and sets
// core.hooksPath. It is safe to run again, and running it again picks up hooks
// added to the chained directory since.
func Install(dir string) (Result, error) {
	var r Result
	common, err := git(dir, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return r, err
	}
	shimDir := filepath.Join(common, Dir)
	r.HooksPath = shimDir

	chained, err := chainedDir(dir, common, shimDir)
	if err != nil {
		return r, err
	}
	r.Chained = chained

	names, err := existingHooks(chained)
	if err != nil {
		return r, err
	}
	for _, g := range Guarded {
		names = appendUnique(names, g)
	}
	sort.Strings(names)

	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return r, err
	}
	// A shim left from an earlier install for a hook that no longer exists in
	// the chained directory is removed: it would run nothing and cost a fork.
	old, _ := filepath.Glob(filepath.Join(shimDir, "*"))
	for _, p := range old {
		if !contains(names, filepath.Base(p)) {
			if err := os.Remove(p); err != nil {
				return r, err
			}
		}
	}
	for _, n := range names {
		if err := writeFile(filepath.Join(shimDir, n), Shim(n, chained), 0o755); err != nil {
			return r, err
		}
	}
	r.Shims = names

	if err := writeFile(filepath.Join(common, chainFile), []byte(chained+"\n"), 0o644); err != nil {
		return r, err
	}
	if _, err := git(dir, "config", "--local", "core.hooksPath", shimDir); err != nil {
		return r, err
	}

	r.Worktrees, err = checkWorktrees(dir, shimDir)
	return r, err
}

// chainedDir is the hook directory git used before pubmirror: the chain recorded
// by an earlier install, else an absolute core.hooksPath, else the common
// directory's hooks.
func chainedDir(dir, common, shimDir string) (string, error) {
	if b, err := os.ReadFile(filepath.Join(common, chainFile)); err == nil {
		if c := strings.TrimSpace(string(b)); c != "" {
			return c, nil
		}
	}
	cur, err := git(dir, "config", "--get", "core.hooksPath")
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 { // unset
			return filepath.Join(common, "hooks"), nil
		}
		return "", err
	}
	switch {
	case cur == shimDir:
		return filepath.Join(common, "hooks"), nil
	case !filepath.IsAbs(cur):
		return "", fmt.Errorf("core.hooksPath is the relative path %q, which each worktree resolves on its own; set it to an absolute path or unset it, then run install again", cur)
	}
	return cur, nil
}

// existingHooks lists the executable hooks in dir, skipping git's samples.
func existingHooks(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil || info.Mode()&0o111 == 0 {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

// checkWorktrees reads core.hooksPath as each worktree of the clone sees it. A
// worktree with its own config.worktree can override the shared value.
func checkWorktrees(dir, want string) ([]WorktreeCheck, error) {
	out, err := git(dir, "worktree", "list", "--porcelain")
	if err != nil {
		return nil, err
	}
	var checks []WorktreeCheck
	for _, line := range strings.Split(out, "\n") {
		p, ok := strings.CutPrefix(line, "worktree ")
		if !ok {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue // pruned or on an unmounted disk
		}
		got, _ := git(p, "config", "--get", "core.hooksPath")
		checks = append(checks, WorktreeCheck{Path: p, HooksPath: got, OK: got == want})
	}
	return checks, nil
}

// Shim is the script for one hook. A guarded hook runs the chained hook first,
// so that pubmirror sees what that hook left, then pubmirror. pubmirror's exit 1
// fails the hook; any other non-zero exit, the binary missing included, is a
// warning and the operation goes on: CI is the binding check.
func Shim(name, chained string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "#!/bin/sh\n# pubmirror hook shim for %s, written by `pubmirror install`.\n", name)
	fmt.Fprintf(&b, "chained=%s\n", shQuote(filepath.Join(chained, name)))
	args, guarded := guardArgs[name]
	if !guarded {
		b.WriteString(`if [ -x "$chained" ]; then exec "$chained" "$@"; fi
exit 0
`)
		return b.Bytes()
	}
	fmt.Fprintf(&b, "hook=%s\nguard=%s\n", name, shQuote(args))
	if name == "pre-push" {
		// Both the chained hook and guard-push read the pushed refs on stdin.
		b.WriteString(`refs=$(mktemp "${TMPDIR:-/tmp}/pubmirror-refs.XXXXXX") || exit 1
trap 'rm -f "$refs"' EXIT
cat >"$refs"
if [ -x "$chained" ]; then "$chained" "$@" <"$refs" || exit $?; fi
`)
	} else {
		b.WriteString(`refs=/dev/null
if [ -x "$chained" ]; then "$chained" "$@" || exit $?; fi
`)
	}
	b.WriteString(`bin=${PUBMIRROR:-pubmirror}
if ! command -v "$bin" >/dev/null 2>&1; then
	echo "pubmirror: $hook: '$bin' not found; not checked. CI is the binding check." >&2
	exit 0
fi
# $guard is split into words on purpose.
"$bin" $guard "$@" <"$refs"
rc=$?
case $rc in
0) exit 0 ;;
1) echo "pubmirror: $hook refused (exit 1); see the findings above." >&2; exit 1 ;;
*) echo "pubmirror: $hook: pubmirror could not run (exit $rc); not checked. CI is the binding check." >&2; exit 0 ;;
esac
`)
	return b.Bytes()
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// writeFile replaces path atomically, so a hook running during install never
// reads half a shim.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pubmirror-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 && stderr.Len() == 0 {
			return "", err // `git config --get` of an unset key
		}
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func appendUnique(xs []string, s string) []string {
	if contains(xs, s) {
		return xs
	}
	return append(xs, s)
}
