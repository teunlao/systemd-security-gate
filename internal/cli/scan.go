package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/teunlao/systemd-security-gate/internal/allowlist"
	"github.com/teunlao/systemd-security-gate/internal/discover"
	"github.com/teunlao/systemd-security-gate/internal/model"
	"github.com/teunlao/systemd-security-gate/internal/offlineroot"
	"github.com/teunlao/systemd-security-gate/internal/report"
	"github.com/teunlao/systemd-security-gate/internal/sarif"
	"github.com/teunlao/systemd-security-gate/internal/systemdanalyze"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	for _, part := range strings.Split(v, "\n") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		*s = append(*s, part)
	}
	return nil
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		repoRoot       = fs.String("repo-root", ".", "Path to repo root")
		threshold      = fs.Float64("threshold", -1, "Fail if overall exposure is greater than this value (required)")
		policyPath     = fs.String("policy", "", "Path to systemd-analyze security policy JSON (optional)")
		allowlistPath  = fs.String("allowlist", "", "Path to allowlist JSON (optional)")
		mode           = fs.String("mode", "enforce", "One of: enforce, report")
		systemdAnalyze = fs.String("systemd-analyze", "systemd-analyze", "Path to systemd-analyze binary")
		topN           = fs.Int("top", 10, "How many highest-exposure checks to show per unit")

		jsonReportPath  = fs.String("json-report", "", "Write combined JSON report to file (optional)")
		sarifReportPath = fs.String("sarif-report", "", "Write SARIF report to file (optional)")
		summaryPath     = fs.String("summary-file", "", "Write Markdown summary to file (optional; defaults to $GITHUB_STEP_SUMMARY if set)")

		paths   stringSliceFlag
		exclude stringSliceFlag
	)

	fs.Var(&paths, "paths", "Glob to find unit files (repeatable). Example: deploy/systemd/**/*.service")
	fs.Var(&exclude, "exclude", "Glob to exclude from matches (repeatable)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *threshold < 0 {
		fmt.Fprintln(stderr, "error: --threshold is required")
		return 2
	}
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "error: at least one --paths is required")
		return 2
	}
	if *mode != "enforce" && *mode != "report" {
		fmt.Fprintln(stderr, "error: --mode must be one of: enforce, report")
		return 2
	}

	repoAbs, err := filepath.Abs(*repoRoot)
	if err != nil {
		fmt.Fprintf(stderr, "error: resolve --repo-root: %v\n", err)
		return 1
	}

	policyAbs := *policyPath
	if policyAbs != "" && !filepath.IsAbs(policyAbs) {
		policyAbs = filepath.Join(repoAbs, policyAbs)
	}

	matches, err := discover.ServiceUnits(repoAbs, paths, exclude)
	if err != nil {
		fmt.Fprintf(stderr, "error: discover unit files: %v\n", err)
		return 1
	}
	if len(matches) == 0 {
		fmt.Fprintln(stderr, "error: no unit files matched --paths")
		return 1
	}
	sort.Strings(matches)

	var allow allowlist.Allowlist
	if *allowlistPath != "" {
		allow, err = allowlist.LoadFile(repoAbs, *allowlistPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: load allowlist: %v\n", err)
			return 1
		}
	}

	builder := offlineroot.Builder{RepoRootAbs: repoAbs}
	root, units, err := builder.Build(matches)
	if err != nil {
		fmt.Fprintf(stderr, "error: build offline root: %v\n", err)
		return 1
	}
	defer os.RemoveAll(root)

	sysdVersion, _ := systemdanalyze.GetVersion(*systemdAnalyze)

	scan := model.ScanReport{
		RepoRoot:        repoAbs,
		SystemdAnalyze:  *systemdAnalyze,
		SystemdVersion:  sysdVersion,
		Threshold:       *threshold,
		PolicyPath:      *policyPath,
		AllowlistPath:   *allowlistPath,
		Mode:            *mode,
		MatchedServices: append([]string(nil), matches...),
	}

	var hasError bool
	var hasUnallowedThreshold bool
	for _, unit := range units {
		unitRes := model.UnitReport{
			UnitName:    unit.UnitName,
			RepoRelPath: unit.RepoRelPath,
		}

		overall, err := systemdanalyze.SecurityOverall(*systemdAnalyze, systemdanalyze.SecurityOverallArgs{
			Root:       root,
			UnitName:   unit.UnitName,
			PolicyPath: policyAbs,
			Threshold:  *threshold,
		})
		if err != nil {
			unitRes.Error = err.Error()
			hasError = true
			scan.Units = append(scan.Units, unitRes)
			continue
		}
		unitRes.OverallExposure = overall.OverallExposure
		unitRes.OverallRating = overall.OverallRating
		unitRes.ThresholdExceeded = overall.ThresholdExceeded

		table, err := systemdanalyze.SecurityTable(*systemdAnalyze, systemdanalyze.SecurityTableArgs{
			Root:       root,
			UnitName:   unit.UnitName,
			PolicyPath: policyAbs,
		})
		if err != nil {
			unitRes.Error = err.Error()
			hasError = true
			scan.Units = append(scan.Units, unitRes)
			continue
		}
		unitRes.Checks = table.Checks

		allIssues := model.Issues(unitRes.Checks)
		unitRes.TopIssues = model.TopIssues(allIssues, *topN)

		if unitRes.ThresholdExceeded {
			if allow.AllowsUnit(unitRes.RepoRelPath) || allow.AllowsUnit(unitRes.UnitName) {
				unitRes.Allowed = true
			} else if allow.AllowsAllIssues(unitRes.RepoRelPath, unitRes.UnitName, allIssues) {
				unitRes.Allowed = true
			} else {
				hasUnallowedThreshold = true
			}
		}

		scan.Units = append(scan.Units, unitRes)
	}

	md := report.MarkdownSummary(scan)
	fmt.Fprintln(stdout, md)

	if *summaryPath == "" {
		if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
			*summaryPath = p
		}
	}
	if *summaryPath != "" {
		f, err := os.OpenFile(*summaryPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintf(stderr, "warning: write summary file: %v\n", err)
		} else {
			if _, err := f.WriteString(md); err != nil {
				fmt.Fprintf(stderr, "warning: write summary file: %v\n", err)
			}
			_ = f.Close()
		}
	}

	if *jsonReportPath != "" {
		b, err := json.MarshalIndent(scan, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "error: build JSON report: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*jsonReportPath, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintf(stderr, "error: write JSON report: %v\n", err)
			return 1
		}
	}

	if *sarifReportPath != "" {
		s := sarif.FromScanReport(scan)
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "error: build SARIF report: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*sarifReportPath, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintf(stderr, "error: write SARIF report: %v\n", err)
			return 1
		}
	}

	if hasError {
		return 1
	}
	if hasUnallowedThreshold && *mode == "enforce" {
		return 1
	}
	return 0
}
