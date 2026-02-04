package systemdanalyze

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/teunlao/systemd-security-gate/internal/model"
)

type SecurityOverallArgs struct {
	Root       string
	UnitName   string
	PolicyPath string
	Threshold  float64
}

type SecurityOverallResult struct {
	OverallExposure   float64
	OverallRating     string
	ThresholdExceeded bool
}

var overallRe = regexp.MustCompile(`Overall exposure level for .*: ([0-9]+(?:\.[0-9]+)?)\s+([A-Z]+)`)

func SecurityOverall(systemdAnalyzePath string, args SecurityOverallArgs) (SecurityOverallResult, error) {
	if args.Root == "" || args.UnitName == "" {
		return SecurityOverallResult{}, fmt.Errorf("Root and UnitName are required")
	}

	cmdArgs := []string{
		"security",
		"--no-pager",
		"--offline=yes",
		"--root=" + args.Root,
		"--threshold=" + trimFloat(args.Threshold),
	}
	if args.PolicyPath != "" {
		cmdArgs = append(cmdArgs, "--security-policy="+args.PolicyPath)
	}
	cmdArgs = append(cmdArgs, args.UnitName)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := run(ctx, systemdAnalyzePath, cmdArgs)
	if err != nil {
		return SecurityOverallResult{}, err
	}

	out := res.Stdout + "\n" + res.Stderr
	m := overallRe.FindStringSubmatch(out)
	if len(m) != 3 {
		return SecurityOverallResult{}, fmt.Errorf("could not parse overall exposure from output (exit=%d): %s", res.ExitCode, snippet(out, 800))
	}

	exposure, err := parseFloat(m[1])
	if err != nil {
		return SecurityOverallResult{}, fmt.Errorf("parse exposure: %w", err)
	}

	return SecurityOverallResult{
		OverallExposure:   exposure,
		OverallRating:     m[2],
		ThresholdExceeded: res.ExitCode != 0,
	}, nil
}

type SecurityTableArgs struct {
	Root       string
	UnitName   string
	PolicyPath string
}

type SecurityTableResult struct {
	Checks []model.SecurityCheck
}

func SecurityTable(systemdAnalyzePath string, args SecurityTableArgs) (SecurityTableResult, error) {
	if args.Root == "" || args.UnitName == "" {
		return SecurityTableResult{}, fmt.Errorf("Root and UnitName are required")
	}

	cmdArgs := []string{
		"security",
		"--no-pager",
		"--offline=yes",
		"--root=" + args.Root,
		"--json=short",
	}
	if args.PolicyPath != "" {
		cmdArgs = append(cmdArgs, "--security-policy="+args.PolicyPath)
	}
	cmdArgs = append(cmdArgs, args.UnitName)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := run(ctx, systemdAnalyzePath, cmdArgs)
	if err != nil {
		return SecurityTableResult{}, err
	}
	if res.ExitCode != 0 {
		out := res.Stdout + "\n" + res.Stderr
		return SecurityTableResult{}, fmt.Errorf("systemd-analyze security --json failed (exit=%d): %s", res.ExitCode, snippet(out, 800))
	}

	var raw []struct {
		Set         any             `json:"set"`
		Name        string          `json:"name"`
		JSONField   string          `json:"json_field"`
		Description string          `json:"description"`
		Exposure    flexibleFloat64 `json:"exposure"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &raw); err != nil {
		return SecurityTableResult{}, fmt.Errorf("parse JSON: %w (output: %s)", err, snippet(res.Stdout, 800))
	}

	checks := make([]model.SecurityCheck, 0, len(raw))
	for _, r := range raw {
		checks = append(checks, model.SecurityCheck{
			Set:         coerceBool(r.Set),
			Name:        strings.TrimSpace(r.Name),
			JSONField:   strings.TrimSpace(r.JSONField),
			Description: strings.TrimSpace(r.Description),
			Exposure:    float64(r.Exposure),
		})
	}

	return SecurityTableResult{Checks: checks}, nil
}

func coerceBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case int:
		return t != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "y":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%.6f", f)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if s == "" {
		return "0"
	}
	return s
}

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

func snippet(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

type flexibleFloat64 float64

func (f *flexibleFloat64) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*f = 0
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if strings.TrimSpace(s) == "" {
			*f = 0
			return nil
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		*f = flexibleFloat64(v)
		return nil
	}
	var v float64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*f = flexibleFloat64(v)
	return nil
}
