package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/publish"
	"github.com/caoer/pubmirror/internal/scan"
	"github.com/caoer/pubmirror/internal/verify"
)

func init() {
	register("verify", "check the public repository from an anonymous clone", runVerify)
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	approve := fs.String("approve", os.Getenv("PUBMIRROR_APPROVE"), "the approval X:H:D that was published")
	url := fs.String("url", "", "clone URL (default: the https form of the manifest's public remote)")
	repoDir := fs.String("repo", ".", "the canonical repository, for the manifest at X")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitCannot
	}
	a, err := publish.ParseApproval(*approve)
	if err != nil {
		return exitFor("verify", err)
	}
	r, err := gitobj.Open(*repoDir)
	if err != nil {
		return exitFor("verify", err)
	}
	dl, err := coreDenylist()
	if err != nil {
		return exitFor("verify", err)
	}
	if d := dl.Hash(); d != a.Denylist {
		fmt.Printf("note: the loaded denylist hashes to %s; the approval was read against %s\n", d, a.Denylist)
	}
	rep, err := verify.Run(verify.Options{
		Repo: r, Commit: a.Commit, Tree: a.Tree, URL: *url,
		Denylist: dl, Tokens: scan.Gitleaks{}, Log: os.Stdout,
	})
	if err != nil {
		return exitFor("verify", err)
	}
	for _, u := range rep.Allowed {
		fmt.Printf("allowed: %s %q in %s (%s), %d times\n", u.Allow.Rule, u.Allow.Match, u.Allow.Path, u.Allow.Reason, u.Count)
	}
	for _, p := range rep.Problems {
		fmt.Println("problem: " + p)
	}
	for _, f := range rep.Findings {
		fmt.Println("finding: " + f.String())
	}
	if rep.Failed() {
		fmt.Printf("verify failed: %s\n", rep.URL)
		return exitFindings
	}
	fmt.Printf("verified: %s main %s has tree %s, history clean\n", rep.URL, rep.PublicTip, a.Tree)
	return exitClean
}
