package sarif

import (
	"fmt"
	"sort"
	"time"

	"github.com/teunlao/systemd-security-gate/internal/model"
)

// Minimal SARIF 2.1.0 structures for GitHub Code Scanning ingestion.

type Report struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Inv     []Invoc  `json:"invocations,omitempty"`
	Results []Result `json:"results,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type Invoc struct {
	ExecutionSuccessful bool      `json:"executionSuccessful"`
	StartTimeUTC        time.Time `json:"startTimeUtc,omitempty"`
	EndTimeUTC          time.Time `json:"endTimeUtc,omitempty"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level,omitempty"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

func FromScanReport(scan model.ScanReport) Report {
	rules := map[string]Rule{}
	var results []Result

	for _, u := range scan.Units {
		if u.Error != "" {
			continue
		}
		if u.Allowed {
			continue
		}
		if !u.ThresholdExceeded {
			continue
		}
		for _, c := range u.TopIssues {
			testID := c.JSONField
			if testID == "" {
				testID = c.Name
			}
			if testID == "" {
				continue
			}
			ruleID := "systemd." + testID
			rules[ruleID] = Rule{ID: ruleID, Name: testID}

			msg := fmt.Sprintf("%s exposure=%.2f: %s", testID, c.Exposure, c.Description)
			results = append(results, Result{
				RuleID:  ruleID,
				Level:   "warning",
				Message: Message{Text: msg},
				Locations: []Location{
					{
						PhysicalLocation: PhysicalLocation{
							ArtifactLocation: ArtifactLocation{URI: u.RepoRelPath},
						},
					},
				},
			})
		}
	}

	var ruleList []Rule
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.SliceStable(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	return Report{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:  "systemd-security-gate",
						Rules: ruleList,
					},
				},
				Results: results,
			},
		},
	}
}
