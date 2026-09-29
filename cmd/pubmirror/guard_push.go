package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/manifest"
)

func init() {
	register("guard-push", "pre-push: refuse the public remote, check each pushed tip", func(args []string) int {
		return guardPush(args, os.Stdin, ".")
	})
}

const zeroOID = "0000000000000000000000000000000000000000"

// pushUpdate is one line git writes to a pre-push hook's stdin.
type pushUpdate struct {
	localRef, localOID, remoteRef, remoteOID string
}

// guardPush runs as git's pre-push hook: args are the remote's name and URL,
// stdin lists the updates. A push to the public remote named by any manifest in
// reach (at HEAD, at each pushed tip, at main and at each remote's main) is
// refused, deletions included. Any other push runs check on each pushed tip.
func guardPush(args []string, stdin io.Reader, dir string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pubmirror guard-push <remote-name> <remote-url>  (refs on stdin, as git's pre-push hook)")
		return exitCannot
	}
	url := args[1]
	updates, err := readUpdates(stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pubmirror guard-push:", err)
		return exitCannot
	}
	repo, err := gitobj.Open(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pubmirror guard-push:", err)
		return exitCannot
	}

	// A worktree on a branch that predates adoption has no manifest at HEAD or
	// at its tips, so main and every remote's main are read as well.
	revs := []string{"HEAD"}
	for _, u := range updates {
		if u.localOID != zeroOID {
			revs = append(revs, u.localOID)
		}
	}
	if out, err := repo.Run("for-each-ref", "--format=%(objectname)", "refs/heads/main", "refs/remotes/*/main"); err == nil {
		revs = append(revs, strings.Fields(string(out))...)
	}
	found := false
	for _, rev := range revs {
		data, ok, err := repo.FileAt(rev, manifest.File)
		if err != nil || !ok {
			continue
		}
		m, err := manifest.Parse(data)
		if err != nil {
			continue // check on that tip reports it
		}
		found = true
		if sameRemote(url, m.Public.Remote) {
			fmt.Fprintf(os.Stderr, "pubmirror guard-push: refused: %s is the public remote (%s at %.12s). Only the publisher writes it.\n", url, manifest.File, rev)
			return exitFindings
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "pubmirror guard-push: no %s at HEAD, at a pushed tip or at a main; the push is not checked\n", manifest.File)
		return exitCannot
	}

	check, ok := commands["check"]
	if !ok {
		fmt.Fprintln(os.Stderr, "pubmirror guard-push: this build has no check command")
		return exitCannot
	}
	rc := exitClean
	for _, u := range updates {
		if u.localOID == zeroOID {
			continue // a deletion carries no content
		}
		switch r := check.run([]string{"--commit", u.localOID}); {
		case r == exitFindings:
			rc = exitFindings
		case r != exitClean && rc == exitClean:
			rc = exitCannot
		}
	}
	return rc
}

func readUpdates(r io.Reader) ([]pushUpdate, error) {
	var us []pushUpdate
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) != 4 {
			return nil, fmt.Errorf("unexpected pre-push line %q", sc.Text())
		}
		us = append(us, pushUpdate{f[0], f[1], f[2], f[3]})
	}
	return us, sc.Err()
}

var (
	urlScheme = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`)
	scpLike   = regexp.MustCompile(`^([^/@:]+@)?([^/:]+):(.*)$`)
)

// sameRemote compares two git URLs by host and path, ignoring the transport,
// the user, a port, a trailing ".git" or "/", and case: git@host:o/r.git,
// ssh://git@host:22/o/r and https://host/o/r are the same repository.
func sameRemote(a, b string) bool {
	na, nb := normalizeRemote(a), normalizeRemote(b)
	return na != "" && na == nb
}

func normalizeRemote(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if loc := urlScheme.FindStringIndex(u); loc != nil {
		u = u[loc[1]:]
		if at := strings.LastIndex(strings.SplitN(u, "/", 2)[0], "@"); at >= 0 {
			u = u[at+1:]
		}
		host, rest, _ := strings.Cut(u, "/")
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		u = host + "/" + rest
	} else if m := scpLike.FindStringSubmatch(u); m != nil {
		u = m[2] + "/" + m[3]
	}
	u = strings.TrimRight(u, "/")
	u = strings.TrimSuffix(u, ".git")
	return strings.TrimRight(u, "/")
}
