package model

import "testing"

func TestIssuesSortAndFilter(t *testing.T) {
	checks := []SecurityCheck{
		{JSONField: "B", Exposure: 0.2},
		{JSONField: "A", Exposure: 0.2},
		{Name: "C", Exposure: 0.5},
		{JSONField: "Zero", Exposure: 0},
	}

	issues := Issues(checks)
	if len(issues) != 3 {
		t.Fatalf("Issues() len = %d, want 3", len(issues))
	}
	if issues[0].Name != "C" {
		t.Fatalf("Issues()[0] = %#v, want C first", issues[0])
	}
	if issues[1].JSONField != "A" || issues[2].JSONField != "B" {
		t.Fatalf("Issues() tie-break order = %#v, want A then B", issues)
	}

	top := TopIssues(checks, 2)
	if len(top) != 2 {
		t.Fatalf("TopIssues() len = %d, want 2", len(top))
	}
	if top[0].Name != "C" || top[1].JSONField != "A" {
		t.Fatalf("TopIssues() = %#v, want C then A", top)
	}
}
