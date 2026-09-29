// Command pubmirror guards what a private repository publishes.
//
// Each subcommand lives in its own file in this package and registers itself
// from init, so two subcommands never edit the same file.
package main

import (
	"fmt"
	"os"
	"sort"
)

// Exit codes, the same for every subcommand.
const (
	exitClean    = 0 // nothing to report
	exitFindings = 1 // the check ran and found something
	exitCannot   = 2 // the check could not run: manifest, denylist, gitleaks, git
)

// A command runs with the arguments after its name and returns an exit code.
type command struct {
	summary string
	run     func(args []string) int
}

var commands = map[string]command{}

// register adds a subcommand. Call it from an init function.
func register(name, summary string, run func(args []string) int) {
	if _, dup := commands[name]; dup {
		panic("pubmirror: subcommand registered twice: " + name)
	}
	commands[name] = command{summary, run}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pubmirror <command> [arguments]")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-12s %s\n", n, commands[n].summary)
	}
	fmt.Fprintln(os.Stderr, "exit codes: 0 clean, 1 findings, 2 could not run")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitCannot)
	}
	c, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "pubmirror: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(exitCannot)
	}
	os.Exit(c.run(os.Args[2:]))
}
