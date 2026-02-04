package report

import (
	"fmt"
	"strings"

	"github.com/teunlao/systemd-security-gate/internal/model"
)

func MarkdownSummary(scan model.ScanReport) string {
	var b strings.Builder
	b.WriteString("## systemd security gate\n\n")
	b.WriteString(fmt.Sprintf("- Threshold: %.2f\n", scan.Threshold))
	if scan.PolicyPath != "" {
		b.WriteString(fmt.Sprintf("- Policy: `%s`\n", scan.PolicyPath))
	}
	if scan.SystemdVersion != "" {
		b.WriteString(fmt.Sprintf("- systemd-analyze: `%s` (%s)\n", scan.SystemdAnalyze, scan.SystemdVersion))
	} else {
		b.WriteString(fmt.Sprintf("- systemd-analyze: `%s`\n", scan.SystemdAnalyze))
	}
	b.WriteString("\n")

	b.WriteString("| Unit | Path | Status | Overall |\n")
	b.WriteString("|------|------|--------|---------|\n")
	for _, u := range scan.Units {
		status := "✅ pass"
		if u.Error != "" {
			status = "❌ error"
		} else if u.ThresholdExceeded && !u.Allowed {
			status = "❌ fail"
		} else if u.ThresholdExceeded && u.Allowed {
			status = "⚠️ allowed"
		}
		overall := ""
		if u.Error != "" {
			overall = u.Error
		} else if u.OverallRating != "" {
			overall = fmt.Sprintf("%.2f %s", u.OverallExposure, u.OverallRating)
		} else {
			overall = fmt.Sprintf("%.2f", u.OverallExposure)
		}
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s |\n", u.UnitName, u.RepoRelPath, status, overall))
	}
	b.WriteString("\n")

	for _, u := range scan.Units {
		if u.Error != "" {
			continue
		}
		if len(u.TopIssues) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("### %s\n\n", u.UnitName))
		if u.RepoRelPath != "" {
			b.WriteString(fmt.Sprintf("- Path: `%s`\n\n", u.RepoRelPath))
		}
		for _, c := range u.TopIssues {
			id := c.JSONField
			if id == "" {
				id = c.Name
			}
			if id == "" {
				id = "(unknown)"
			}
			desc := c.Description
			if desc == "" {
				desc = c.Name
			}
			b.WriteString(fmt.Sprintf("- `%s` exposure=%.2f: %s\n", id, c.Exposure, desc))
		}
		b.WriteString("\n")
	}

	return b.String()
}
