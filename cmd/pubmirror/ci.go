package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func init() {
	register("ci", "the publisher image's entrypoint: check or publish, as the step's mode setting says", func(args []string) int {
		return runCI(args, os.Stdout, os.Stderr)
	})
}

// runCI is the publisher image's entrypoint. CI runs it as a plugin step, so
// its inputs are settings (PLUGIN_*) and CI's own variables:
//
//	PLUGIN_MODE       check: check CI_COMMIT_SHA; publish: publish
//	PLUGIN_DENYLIST   the denylist text, when PUBMIRROR_DENYLIST is unset
//
// A step that runs commands replaces the entrypoint, and CI releases an
// image-limited secret to plugin steps only, so the denylist and the deploy key
// reach nothing but this function.
func runCI(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: pubmirror ci  (the image's entrypoint; set the step's mode to check or publish)")
		return exitCannot
	}
	switch mode := os.Getenv("PLUGIN_MODE"); mode {
	case "check":
		sha := os.Getenv("CI_COMMIT_SHA")
		if sha == "" {
			fmt.Fprintln(stderr, "pubmirror ci: CI_COMMIT_SHA is unset")
			return exitCannot
		}
		if os.Getenv("PUBMIRROR_DENYLIST") == "" && os.Getenv("PLUGIN_DENYLIST") != "" {
			dir, err := os.MkdirTemp("", "pubmirror-")
			if err != nil {
				fmt.Fprintln(stderr, "pubmirror ci:", err)
				return exitCannot
			}
			defer os.RemoveAll(dir)
			p := filepath.Join(dir, "denylist.txt")
			if err := os.WriteFile(p, []byte(os.Getenv("PLUGIN_DENYLIST")), 0o600); err != nil {
				fmt.Fprintln(stderr, "pubmirror ci:", err)
				return exitCannot
			}
			os.Setenv("PUBMIRROR_DENYLIST", p)
		}
		return check([]string{"--commit", sha}, ".", stdout, stderr)
	case "publish":
		return commands["publish"].run(nil)
	default:
		fmt.Fprintf(stderr, "pubmirror ci: the step's mode setting is %q; set it to check or publish\n", mode)
		return exitCannot
	}
}
