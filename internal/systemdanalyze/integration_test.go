package systemdanalyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetVersion_Stub(t *testing.T) {
	stub := writeSystemdAnalyzeStub(t, stubCfg{})
	got, err := GetVersion(stub)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if got != "systemd 252 (stub)" {
		t.Fatalf("GetVersion() = %q, want %q", got, "systemd 252 (stub)")
	}
}

func TestSecurityOverall_ThresholdExceeded(t *testing.T) {
	stub := writeSystemdAnalyzeStub(t, stubCfg{})
	root := t.TempDir()

	got, err := SecurityOverall(stub, SecurityOverallArgs{
		Root:      root,
		UnitName:  "myapp.service",
		Threshold: 6.0,
	})
	if err != nil {
		t.Fatalf("SecurityOverall() error = %v", err)
	}
	if got.OverallExposure != 7.2 {
		t.Fatalf("OverallExposure = %v, want 7.2", got.OverallExposure)
	}
	if got.OverallRating != "EXPOSED" {
		t.Fatalf("OverallRating = %q, want EXPOSED", got.OverallRating)
	}
	if !got.ThresholdExceeded {
		t.Fatalf("ThresholdExceeded = false, want true")
	}
}

func TestSecurityOverall_PassWhenThresholdHigh(t *testing.T) {
	stub := writeSystemdAnalyzeStub(t, stubCfg{})
	root := t.TempDir()

	got, err := SecurityOverall(stub, SecurityOverallArgs{
		Root:      root,
		UnitName:  "myapp.service",
		Threshold: 9.0,
	})
	if err != nil {
		t.Fatalf("SecurityOverall() error = %v", err)
	}
	if got.ThresholdExceeded {
		t.Fatalf("ThresholdExceeded = true, want false")
	}
}

func TestSecurityTable_ParsesJSON(t *testing.T) {
	stub := writeSystemdAnalyzeStub(t, stubCfg{})
	root := t.TempDir()

	got, err := SecurityTable(stub, SecurityTableArgs{
		Root:     root,
		UnitName: "myapp.service",
	})
	if err != nil {
		t.Fatalf("SecurityTable() error = %v", err)
	}
	if len(got.Checks) != 2 {
		t.Fatalf("checks len = %d, want 2", len(got.Checks))
	}
	if got.Checks[0].JSONField != "PrivateNetwork" {
		t.Fatalf("checks[0].JSONField = %q, want PrivateNetwork", got.Checks[0].JSONField)
	}
	if got.Checks[0].Exposure <= 0 {
		t.Fatalf("checks[0].Exposure = %v, want >0", got.Checks[0].Exposure)
	}
}

func TestSecurityTable_ErrorsOnNonZeroExit(t *testing.T) {
	stub := writeSystemdAnalyzeStub(t, stubCfg{failJSON: true})
	root := t.TempDir()

	_, err := SecurityTable(stub, SecurityTableArgs{
		Root:     root,
		UnitName: "myapp.service",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "exit=") {
		t.Fatalf("expected exit code in error, got: %v", err)
	}
}

type stubCfg struct {
	failJSON bool
}

func writeSystemdAnalyzeStub(t *testing.T, cfg stubCfg) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "systemd-analyze")

	failJSON := "0"
	if cfg.failJSON {
		failJSON = "1"
	}

	script := `#!/usr/bin/env sh
set -eu

FAIL_JSON="` + failJSON + `"

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
      if [ "$FAIL_JSON" = "1" ]; then
        echo "json failed" >&2
        exit 2
      fi
      cat <<'JSON'
[
  {"set":false,"name":"PrivateNetwork=","json_field":"PrivateNetwork","description":"Service has access to the host's network","exposure":"0.5"},
  {"set":true,"name":"NoNewPrivileges=","json_field":"NoNewPrivileges","description":"Service cannot gain new privileges","exposure":null}
]
JSON
      exit 0
      ;;
  esac

  echo "→ Overall exposure level for $unit: 7.2 EXPOSED 🙂"
  awk -v e="7.2" -v t="$threshold" 'BEGIN{exit (e>t)?1:0}'
  exit $?
fi

echo "unsupported args: $*" >&2
exit 2
`

	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return path
}
