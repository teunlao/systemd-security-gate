package main

import (
	"os"

	"github.com/teunlao/systemd-security-gate/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args, os.Stdout, os.Stderr))
}
