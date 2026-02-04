package allowlist

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/teunlao/systemd-security-gate/internal/model"
)

func TestAllowlistAllowsAllIssues(t *testing.T) {
	repo := t.TempDir()
	allowPath := filepath.Join(repo, "allow.json")
	if err := os.WriteFile(allowPath, []byte(`{
  "allowTests": [
    { "unit": "deploy/systemd/myapp.service", "test": "PrivateNetwork" },
    { "unit": "deploy/systemd/myapp.service", "test": "ProtectSystem" }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	a, err := LoadFile(repo, allowPath)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	issues := []model.SecurityCheck{
		{JSONField: "PrivateNetwork", Exposure: 0.5},
		{JSONField: "ProtectSystem", Exposure: 0.4},
	}
	if !a.AllowsAllIssues("deploy/systemd/myapp.service", "myapp.service", issues) {
		t.Fatalf("expected issues to be allowlisted")
	}
}

func TestAllowlistUnitAllow(t *testing.T) {
	a := Allowlist{AllowUnits: []string{"legacy.service"}}
	if !a.AllowsUnit("legacy.service") {
		t.Fatalf("expected unit to be allowed")
	}
	if a.AllowsUnit("other.service") {
		t.Fatalf("expected other unit to be disallowed")
	}
}
