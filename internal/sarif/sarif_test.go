package sarif

import (
	"testing"

	"github.com/teunlao/systemd-security-gate/internal/model"
)

func TestFromScanReportSortsRules(t *testing.T) {
	scan := model.ScanReport{
		Threshold: 6,
		Units: []model.UnitReport{
			{
				UnitName:          "a.service",
				RepoRelPath:       "deploy/a.service",
				ThresholdExceeded: true,
				TopIssues: []model.SecurityCheck{
					{JSONField: "Zeta", Exposure: 1, Description: "z"},
					{JSONField: "Alpha", Exposure: 1, Description: "a"},
				},
			},
		},
	}

	r := FromScanReport(scan)
	if len(r.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(r.Runs))
	}
	rules := r.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("rules len = %d, want 2", len(rules))
	}
	if rules[0].ID != "systemd.Alpha" || rules[1].ID != "systemd.Zeta" {
		t.Fatalf("rules not sorted: %#v", rules)
	}
}
