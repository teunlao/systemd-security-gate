package allowlist

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/teunlao/systemd-security-gate/internal/model"
)

type Allowlist struct {
	AllowUnits []string `json:"allowUnits,omitempty"`
	AllowTests []struct {
		Unit string `json:"unit"`
		Test string `json:"test"`
	} `json:"allowTests,omitempty"`
}

func LoadFile(repoRootAbs string, path string) (Allowlist, error) {
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(repoRootAbs, path)
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return Allowlist{}, err
	}
	var a Allowlist
	if err := json.Unmarshal(b, &a); err != nil {
		return Allowlist{}, fmt.Errorf("parse %s: %w", path, err)
	}
	for i := range a.AllowUnits {
		a.AllowUnits[i] = normalizeUnitKey(a.AllowUnits[i])
	}
	for i := range a.AllowTests {
		a.AllowTests[i].Unit = normalizeUnitKey(a.AllowTests[i].Unit)
		a.AllowTests[i].Test = strings.TrimSpace(a.AllowTests[i].Test)
	}
	return a, nil
}

func (a Allowlist) AllowsUnit(unitKey string) bool {
	if unitKey == "" {
		return false
	}
	unitKey = normalizeUnitKey(unitKey)
	for _, u := range a.AllowUnits {
		if u == unitKey {
			return true
		}
	}
	return false
}

func (a Allowlist) AllowsAllIssues(repoRelPath string, unitName string, issues []model.SecurityCheck) bool {
	if len(issues) == 0 {
		return true
	}
	unitKeys := []string{normalizeUnitKey(repoRelPath), normalizeUnitKey(unitName)}

	for _, issue := range issues {
		testID := issue.JSONField
		if testID == "" {
			testID = issue.Name
		}
		if testID == "" {
			return false
		}
		allowed := false
		for _, k := range unitKeys {
			if a.allowsTest(k, testID) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

func (a Allowlist) allowsTest(unitKey string, testID string) bool {
	unitKey = normalizeUnitKey(unitKey)
	testID = strings.TrimSpace(testID)
	for _, t := range a.AllowTests {
		if t.Unit == unitKey && t.Test == testID {
			return true
		}
	}
	return false
}

func normalizeUnitKey(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "./")
	s = filepath.ToSlash(s)
	return s
}
