package main

import (
	"fmt"
	"os"

	"github.com/caoer/pubmirror/internal/hooks"
)

func init() {
	register("install", "write the hook shims and set core.hooksPath", runInstall)
}

func runInstall(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: pubmirror install")
		return exitCannot
	}
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pubmirror install:", err)
		return exitCannot
	}
	r, err := hooks.Install(wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pubmirror install:", err)
		return exitCannot
	}
	fmt.Printf("core.hooksPath = %s\n", r.HooksPath)
	fmt.Printf("chained hooks from %s\n", r.Chained)
	fmt.Printf("shims: %v\n", r.Shims)
	bad := 0
	for _, w := range r.Worktrees {
		mark := "ok"
		if !w.OK {
			mark = fmt.Sprintf("OVERRIDDEN: resolves %q (a config.worktree setting)", w.HooksPath)
			bad++
		}
		fmt.Printf("worktree %s: %s\n", w.Path, mark)
	}
	if bad > 0 {
		return exitCannot
	}
	return exitClean
}
