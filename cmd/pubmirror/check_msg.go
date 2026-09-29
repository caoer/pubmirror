package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/manifest"
	"github.com/caoer/pubmirror/internal/scan"
)

func init() {
	register("check-msg", "commit-msg: exact mode, scan the message and the author and committer", func(args []string) int {
		return checkMsg(args, ".", os.Stdout, os.Stderr)
	})
}

// checkMsg runs as git's commit-msg hook. It reads the manifest from the index,
// the commit being made. In snapshot mode no canonical message is published,
// so there is nothing to check. In exact mode the message is scanned and the
// author and committer git is about to record must be the manifest's author.
func checkMsg(args []string, cwd string, stdout, stderr io.Writer) int {
	var dl *scan.Denylist
	fail := func(format string, a ...any) int {
		fmt.Fprintln(stderr, dl.Mask(fmt.Sprintf("pubmirror check-msg: "+format, a...)))
		return exitCannot
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: pubmirror check-msg <message-file>  (as git's commit-msg hook)")
		return exitCannot
	}
	repo, err := gitobj.Open(cwd)
	if err != nil {
		return fail("%v", err)
	}
	data, err := repo.Run("cat-file", "blob", ":"+manifest.File)
	if err != nil {
		return fail("no %s in the index", manifest.File)
	}
	m, err := manifest.Parse(data)
	if err != nil {
		return fail("%v", err)
	}
	if m.Mode != manifest.ModeExact {
		return exitClean
	}

	path, err := scan.DenylistPath()
	if err != nil {
		return fail("%v", err)
	}
	if dl, err = scan.LoadDenylist(path); err != nil {
		return fail("%v", err)
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return fail("%v", err)
	}
	author, err := ident(repo, "GIT_AUTHOR_IDENT")
	if err != nil {
		return fail("%v", err)
	}
	committer, err := ident(repo, "GIT_COMMITTER_IDENT")
	if err != nil {
		return fail("%v", err)
	}
	c := scan.Commit{ID: "(new)", Author: author, Committer: committer, Message: stripComments(string(raw))}
	rep, err := scan.Scan(config(dl, m, ""), nil, []scan.Commit{c})
	if err != nil {
		return fail("%v", err)
	}
	return report(dl, "commit message", 0, nil, rep, stdout)
}

// ident returns git's "Name <address>" for GIT_AUTHOR_IDENT or
// GIT_COMMITTER_IDENT, without the timestamp.
func ident(r *gitobj.Repo, which string) (string, error) {
	out, err := r.Run("var", which)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(out))
	if i := strings.LastIndex(s, ">"); i >= 0 {
		s = s[:i+1]
	}
	return s, nil
}

// stripComments drops what git drops from a message under the default
// cleanup: lines starting with '#' and everything below a scissors line.
func stripComments(msg string) string {
	var keep []string
	for _, l := range strings.Split(msg, "\n") {
		if strings.HasPrefix(l, "# ------------------------ >8 ------------------------") {
			break
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		keep = append(keep, l)
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}
