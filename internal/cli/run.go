package cli

import (
	"fmt"
	"io"
)

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, usage())
		return 2
	}

	switch args[1] {
	case "scan":
		return runScan(args[2:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage())
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n%s", args[1], usage())
		return 2
	}
}

func usage() string {
	return `ssg - systemd security gate

Usage:
  ssg scan [flags]

Commands:
  scan   Scan .service units in a repo and gate on systemd-analyze security

Run "ssg scan -h" for scan flags.
`
}
