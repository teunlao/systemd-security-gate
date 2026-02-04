package report

import (
	"strings"
	"testing"

	"github.com/teunlao/systemd-security-gate/internal/model"
)

func TestMarkdownSummaryIncludesOnlyFailDetails(t *testing.T) {
	scan := model.ScanReport{
		Threshold:      6,
		Mode:           "enforce",
		SystemdAnalyze: "systemd-analyze",
		Units: []model.UnitReport{
			{
				UnitName:          "pass.service",
				RepoRelPath:       "deploy/pass.service",
				OverallExposure:   4.0,
				OverallRating:     "OK",
				ThresholdExceeded: false,
				TopIssues: []model.SecurityCheck{
					{JSONField: "PrivateNetwork", Exposure: 0.5, Description: "pass unit issue"},
				},
			},
			{
				UnitName:          "fail.service",
				RepoRelPath:       "deploy/fail.service",
				OverallExposure:   7.0,
				OverallRating:     "EXPOSED",
				ThresholdExceeded: true,
				TopIssues: []model.SecurityCheck{
					{JSONField: "PrivateNetwork", Exposure: 0.5, Description: "fail unit issue"},
				},
			},
			{
				UnitName:    "err.service",
				RepoRelPath: "deploy/err.service",
				Error:       "boom",
			},
		},
	}

	md := MarkdownSummary(scan)
	if !strings.Contains(md, "Mode: enforce") {
		t.Fatalf("expected mode in summary, got:\n%s", md)
	}

	if !strings.Contains(md, "`pass.service`") || !strings.Contains(md, "✅ pass") {
		t.Fatalf("expected pass unit row, got:\n%s", md)
	}
	if !strings.Contains(md, "`fail.service`") || !strings.Contains(md, "❌ fail") {
		t.Fatalf("expected fail unit row, got:\n%s", md)
	}
	if !strings.Contains(md, "`err.service`") || !strings.Contains(md, "❌ error") {
		t.Fatalf("expected error unit row, got:\n%s", md)
	}

	if strings.Contains(md, "### pass.service") {
		t.Fatalf("did not expect details section for pass unit, got:\n%s", md)
	}
	if !strings.Contains(md, "### fail.service") {
		t.Fatalf("expected details section for fail unit, got:\n%s", md)
	}
	if !strings.Contains(md, "### err.service") || !strings.Contains(md, "Error: boom") {
		t.Fatalf("expected details section for error unit, got:\n%s", md)
	}
}
