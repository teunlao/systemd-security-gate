package model

import (
	"sort"
)

type SecurityCheck struct {
	Set         bool    `json:"set"`
	Name        string  `json:"name"`
	JSONField   string  `json:"json_field"`
	Description string  `json:"description"`
	Exposure    float64 `json:"exposure"`
}

type UnitFile struct {
	UnitName    string
	RepoRelPath string
}

type UnitReport struct {
	UnitName    string `json:"unitName"`
	RepoRelPath string `json:"repoRelPath"`

	OverallExposure   float64 `json:"overallExposure,omitempty"`
	OverallRating     string  `json:"overallRating,omitempty"`
	ThresholdExceeded bool    `json:"thresholdExceeded,omitempty"`
	Allowed           bool    `json:"allowed,omitempty"`

	Checks    []SecurityCheck `json:"checks,omitempty"`
	TopIssues []SecurityCheck `json:"topIssues,omitempty"`

	Error string `json:"error,omitempty"`
}

type ScanReport struct {
	RepoRoot        string   `json:"repoRoot"`
	SystemdAnalyze  string   `json:"systemdAnalyze"`
	SystemdVersion  string   `json:"systemdVersion,omitempty"`
	Threshold       float64  `json:"threshold"`
	PolicyPath      string   `json:"policyPath,omitempty"`
	AllowlistPath   string   `json:"allowlistPath,omitempty"`
	Mode            string   `json:"mode"`
	MatchedServices []string `json:"matchedServices"`

	Units []UnitReport `json:"units"`
}

func checkID(c SecurityCheck) string {
	if c.JSONField != "" {
		return c.JSONField
	}
	return c.Name
}

func Issues(checks []SecurityCheck) []SecurityCheck {
	var issues []SecurityCheck
	for _, c := range checks {
		if c.Exposure > 0 {
			issues = append(issues, c)
		}
	}
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Exposure == issues[j].Exposure {
			return checkID(issues[i]) < checkID(issues[j])
		}
		return issues[i].Exposure > issues[j].Exposure
	})
	return issues
}

func TopIssues(checks []SecurityCheck, n int) []SecurityCheck {
	if n <= 0 {
		return nil
	}
	issues := Issues(checks)
	if len(issues) > n {
		issues = issues[:n]
	}
	return issues
}
