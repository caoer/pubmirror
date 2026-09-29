package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/manifest"
	"github.com/caoer/pubmirror/internal/scan"
)

func init() {
	register("guard-receive", "pre-receive on the canonical forge: refuse a push that carries a finding", func(args []string) int {
		return guardReceive(args, os.Stdin, ".", os.Stderr)
	})
}

// receiveUpdate is one line git writes to a pre-receive hook's stdin.
type receiveUpdate struct {
	oldOID, newOID, ref string
}

// guardReceive runs as the pre-receive hook of a canonical repository on the
// forge; stdin lists the updates. Each ref is judged by the manifest at its new
// tip:
//
//   - no manifest, a deletion, or a tip that is not a commit: not judged;
//   - exact: every commit the push brings into the repository — blobs,
//     messages and identities — and the message and tagger of an annotated
//     tag. Commits already in the repository are not judged again;
//   - snapshot: a push to main, the public set of the new tip, which is what a
//     publish would carry. Other refs are not judged.
//
// 0 accepts. A finding (1) and a check that could not run (2) both refuse: the
// forge accepts nothing it could not judge. The denylist is loaded only when a
// ref is judged, so a repository without a manifest never needs it.
func guardReceive(args []string, stdin io.Reader, dir string, w io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(w, "usage: pubmirror guard-receive  (refs on stdin, as git's pre-receive hook)")
		return exitCannot
	}
	updates, err := readReceive(stdin)
	if err != nil {
		fmt.Fprintln(w, "pubmirror guard-receive: refused, could not read the push:", err)
		return exitCannot
	}
	repo, err := gitobj.Open(dir)
	if err != nil {
		fmt.Fprintln(w, "pubmirror guard-receive: refused, could not open the repository:", err)
		return exitCannot
	}
	g := &receiveGuard{repo: repo, w: w}
	rc := exitClean
	for _, u := range updates {
		switch r := g.judge(u); {
		case r == exitFindings:
			rc = exitFindings
			fmt.Fprintf(w, "pubmirror guard-receive: refused %s: remove the findings above from the pushed commits and push again.\n", g.mask(u.ref))
		case r != exitClean:
			if rc == exitClean {
				rc = exitCannot
			}
			fmt.Fprintf(w, "pubmirror guard-receive: refused %s: the check could not run, and this forge accepts nothing it could not judge.\n", g.mask(u.ref))
		}
	}
	return rc
}

type receiveGuard struct {
	repo   *gitobj.Repo
	w      io.Writer
	dl     *scan.Denylist
	judged []string // exact-mode tips judged earlier in this push
}

func (g *receiveGuard) mask(s string) string { return g.dl.Mask(s) }

func (g *receiveGuard) fail(format string, a ...any) int {
	fmt.Fprintln(g.w, g.mask(fmt.Sprintf("pubmirror guard-receive: "+format, a...)))
	return exitCannot
}

func (g *receiveGuard) judge(u receiveUpdate) int {
	if u.newOID == zeroOID {
		return exitClean // a deletion carries no content
	}
	// Peel annotated tags down to the commit; each tag object is judged too.
	var tags []scan.Commit
	obj := u.newOID
	typ, err := g.repo.Type(obj)
	if err != nil {
		return g.fail("%s: %v", u.ref, err)
	}
	for typ == "tag" {
		t, err := g.repo.ReadTag(obj)
		if err != nil {
			return g.fail("%s: %v", u.ref, err)
		}
		tagger := fmt.Sprintf("%s <%s>", t.TaggerName, t.TaggerMail)
		tags = append(tags, scan.Commit{Kind: "tag", ID: t.Hash, Author: tagger, Committer: tagger, Message: t.Message})
		obj, typ = t.Object, t.Type
	}
	if typ != "commit" {
		return exitClean // a tag of a tree or a blob carries no manifest
	}

	data, ok, err := g.repo.FileAt(obj, manifest.File)
	if err != nil {
		return g.fail("%s: %v", u.ref, err)
	}
	if !ok {
		return exitClean
	}
	m, err := manifest.Parse(data)
	if err != nil {
		return g.fail("%s: %s at %.12s: %v", u.ref, manifest.File, obj, err)
	}
	if m.Mode == manifest.ModeSnapshot && u.ref != "refs/heads/main" {
		return exitClean // snapshot mode publishes main only
	}
	if g.dl == nil {
		p, err := scan.DenylistPath()
		if err != nil {
			return g.fail("%v", err)
		}
		if g.dl, err = scan.LoadDenylist(p); err != nil {
			return g.fail("%v", err)
		}
	}

	// A clean ref shows its summary line only; a refused one, the whole report.
	var buf bytes.Buffer
	var rc int
	if m.Mode == manifest.ModeExact {
		revs := append([]string{obj, "--not", "--all"}, g.judged...)
		label := "push " + u.ref + " " + short(u.newOID)
		if u.oldOID != zeroOID {
			label = "push " + u.ref + " " + short(u.oldOID) + ".." + short(u.newOID)
		}
		rc = judgeHistory(g.repo, g.dl, m, revs, tags, label, &buf, &buf)
		g.judged = append(g.judged, obj)
	} else {
		in, err := commitInput(g.repo, obj)
		if err != nil {
			return g.fail("%s: %v", u.ref, err)
		}
		in.what = "push " + u.ref + " " + short(obj) + ", public set"
		rc = judge(g.dl, in, &buf, &buf)
	}
	out := buf.String()
	if rc == exitClean {
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		out = lines[len(lines)-1] + "\n"
	}
	io.WriteString(g.w, out)
	return rc
}

func readReceive(r io.Reader) ([]receiveUpdate, error) {
	var us []receiveUpdate
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("unexpected pre-receive line %q", sc.Text())
		}
		us = append(us, receiveUpdate{f[0], f[1], f[2]})
	}
	return us, sc.Err()
}
