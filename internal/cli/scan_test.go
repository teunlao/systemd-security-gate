package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teunlao/systemd-security-gate/internal/model"
	"github.com/teunlao/systemd-security-gate/internal/sarif"
)

func TestScanEnforceFailsWithoutAllowlist(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "deploy/systemd/myapp.service"), "[Service]\nExecStart=/bin/true\n")

	stub := writeSystemdAnalyzeStub(t, repo, stubOptions{
		exposure: 7.2,
		rating:   "EXPOSED",
	})

	outDir := t.TempDir()
	jsonReport := filepath.Join(outDir, "ssg.json")
	sarifReport := filepath.Join(outDir, "ssg.sarif")

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"ssg", "scan",
		"--repo-root", repo,
		"--paths", "deploy/systemd/**/*.service",
		"--threshold", "6.0",
		"--systemd-analyze", stub,
		"--json-report", jsonReport,
		"--sarif-report", sarifReport,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "❌ fail") {
		t.Fatalf("expected fail in stdout, got:\n%s", stdout.String())
	}

	var report model.ScanReport
	mustReadJSON(t, jsonReport, &report)
	if len(report.Units) != 1 {
		t.Fatalf("expected 1 unit in json report, got %d", len(report.Units))
	}

	var sarifReportObj sarif.Report
	mustReadJSON(t, sarifReport, &sarifReportObj)
	if len(sarifReportObj.Runs) != 1 {
		t.Fatalf("sarif runs len = %d, want 1", len(sarifReportObj.Runs))
	}
	if len(sarifReportObj.Runs[0].Results) == 0 {
		t.Fatalf("expected sarif results, got none")
	}
}

func TestScanAllowlistAllows(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "deploy/systemd/myapp.service"), "[Service]\nExecStart=/bin/true\n")
	mustWrite(t, filepath.Join(repo, "allow.json"), `{
  "allowTests": [
    { "unit": "deploy/systemd/myapp.service", "test": "PrivateNetwork" },
    { "unit": "deploy/systemd/myapp.service", "test": "ProtectSystem" }
  ]
}`)

	stub := writeSystemdAnalyzeStub(t, repo, stubOptions{
		exposure: 7.2,
		rating:   "EXPOSED",
	})

	outDir := t.TempDir()
	sarifReport := filepath.Join(outDir, "ssg.sarif")

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"ssg", "scan",
		"--repo-root", repo,
		"--paths", "deploy/systemd/**/*.service",
		"--threshold", "6.0",
		"--allowlist", "allow.json",
		"--systemd-analyze", stub,
		"--sarif-report", sarifReport,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "⚠️ allowed") {
		t.Fatalf("expected allowed in stdout, got:\n%s", stdout.String())
	}

	var sarifReportObj sarif.Report
	mustReadJSON(t, sarifReport, &sarifReportObj)
	if len(sarifReportObj.Runs) != 1 {
		t.Fatalf("sarif runs len = %d, want 1", len(sarifReportObj.Runs))
	}
	if len(sarifReportObj.Runs[0].Results) != 0 {
		t.Fatalf("expected no sarif results for allowlisted unit, got %d", len(sarifReportObj.Runs[0].Results))
	}
}

func TestScanReportModeDoesNotFailOnThreshold(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "deploy/systemd/myapp.service"), "[Service]\nExecStart=/bin/true\n")

	stub := writeSystemdAnalyzeStub(t, repo, stubOptions{
		exposure: 7.2,
		rating:   "EXPOSED",
	})

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"ssg", "scan",
		"--repo-root", repo,
		"--paths", "deploy/systemd/**/*.service",
		"--threshold", "6.0",
		"--mode", "report",
		"--systemd-analyze", stub,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "❌ fail") {
		t.Fatalf("expected fail in stdout, got:\n%s", stdout.String())
	}
}

func TestScanReportModeStillFailsOnAnalysisError(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "deploy/systemd/myapp.service"), "[Service]\nExecStart=/bin/true\n")

	stub := writeSystemdAnalyzeStub(t, repo, stubOptions{
		failOverall: true,
	})

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"ssg", "scan",
		"--repo-root", repo,
		"--paths", "deploy/systemd/**/*.service",
		"--threshold", "6.0",
		"--mode", "report",
		"--systemd-analyze", stub,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "❌ error") {
		t.Fatalf("expected error in stdout, got:\n%s", stdout.String())
	}
}

func TestScanWritesGithubStepSummary(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "deploy/systemd/myapp.service"), "[Service]\nExecStart=/bin/true\n")

	stub := writeSystemdAnalyzeStub(t, repo, stubOptions{
		exposure: 7.2,
		rating:   "EXPOSED",
	})

	summary := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"ssg", "scan",
		"--repo-root", repo,
		"--paths", "deploy/systemd/**/*.service",
		"--threshold", "6.0",
		"--mode", "report",
		"--systemd-analyze", stub,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}

	b, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(b), "## systemd security gate") {
		t.Fatalf("expected summary file to contain header, got:\n%s", string(b))
	}
}

type stubOptions struct {
	exposure    float64
	rating      string
	failOverall bool
}

func writeSystemdAnalyzeStub(t *testing.T, repoRoot string, opts stubOptions) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "systemd-analyze")

	exposure := opts.exposure
	if exposure == 0 {
		exposure = 7.2
	}
	rating := opts.rating
	if rating == "" {
		rating = "EXPOSED"
	}

	overallBlock := `echo "→ Overall exposure level for $unit: ` + floatStr(exposure) + ` ` + rating + ` 🙂"
awk -v e="` + floatStr(exposure) + `" -v t="$threshold" 'BEGIN{exit (e>t)?1:0}'
exit $?`
	if opts.failOverall {
		overallBlock = `echo "boom" >&2
exit 2`
	}

	script := `#!/usr/bin/env sh
set -eu

if [ "${1-}" = "--version" ]; then
  echo "systemd 252 (stub)"
  exit 0
fi

if [ "${1-}" = "security" ]; then
  unit=""
  threshold="100"
  for a in "$@"; do
    unit="$a"
    case "$a" in
      --threshold=*)
        threshold="${a#--threshold=}"
        ;;
    esac
  done

  case " $* " in
    *" --json=short "*) 
      cat <<'JSON'
[
  {"set":false,"name":"PrivateNetwork=","json_field":"PrivateNetwork","description":"Service has access to the host's network","exposure":"0.5"},
  {"set":false,"name":"ProtectSystem=","json_field":"ProtectSystem","description":"Service has full access to the OS","exposure":0.4},
  {"set":true,"name":"NoNewPrivileges=","json_field":"NoNewPrivileges","description":"Service cannot gain new privileges","exposure":null}
]
JSON
      exit 0
      ;;
  esac

  ` + overallBlock + `
fi

echo "unsupported args: $*" >&2
exit 2
`

	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return path
}

func floatStr(f float64) string {
	b, _ := json.Marshal(f)
	return strings.TrimSpace(string(b))
}

func mustReadJSON(t *testing.T, path string, out any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, string(b))
	}
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
