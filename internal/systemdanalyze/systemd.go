package systemdanalyze

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type cmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func run(ctx context.Context, exe string, args []string) (cmdResult, error) {
	cmd := exec.CommandContext(ctx, exe, args...)

	cmd.Env = append(os.Environ(),
		"LC_ALL=C",
		"LANG=C",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := errorAs(err, &ee); ok {
			exitCode = ee.ExitCode()
		} else {
			return cmdResult{}, err
		}
	}

	return cmdResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}, nil
}

func GetVersion(systemdAnalyzePath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := run(ctx, systemdAnalyzePath, []string{"--version"})
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.Split(res.Stdout, "\n")[0])
	return line, nil
}

// errorAs is a tiny local helper to avoid importing errors in multiple files.
func errorAs(err error, target any) bool {
	switch t := target.(type) {
	case **exec.ExitError:
		ee, ok := err.(*exec.ExitError)
		if ok {
			*t = ee
			return true
		}
		return false
	default:
		panic(fmt.Sprintf("unsupported target type %T", target))
	}
}
