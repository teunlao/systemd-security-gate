package systemdanalyze

import (
	"encoding/json"
	"testing"
)

func TestOverallRegex(t *testing.T) {
	out := "→ Overall exposure level for myapp.service: 4.1 OK 🙂\n"
	m := overallRe.FindStringSubmatch(out)
	if len(m) != 3 {
		t.Fatalf("expected match, got %#v", m)
	}
	if m[1] != "4.1" {
		t.Fatalf("exposure = %q, want 4.1", m[1])
	}
	if m[2] != "OK" {
		t.Fatalf("rating = %q, want OK", m[2])
	}
}

func TestCoerceBool(t *testing.T) {
	tests := []struct {
		in   any
		want bool
	}{
		{true, true},
		{false, false},
		{float64(1), true},
		{float64(0), false},
		{"yes", true},
		{"no", false},
	}
	for _, tc := range tests {
		if got := coerceBool(tc.in); got != tc.want {
			t.Fatalf("coerceBool(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFlexibleFloat64_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{in: `0.25`, want: 0.25},
		{in: `"0.25"`, want: 0.25},
		{in: `null`, want: 0},
		{in: `""`, want: 0},
		{in: `"  "`, want: 0},
		{in: `"nope"`, wantErr: true},
	}

	for _, tc := range tests {
		var f flexibleFloat64
		err := json.Unmarshal([]byte(tc.in), &f)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("json.Unmarshal(%s) error = nil, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("json.Unmarshal(%s) error = %v", tc.in, err)
		}
		if got := float64(f); got != tc.want {
			t.Fatalf("json.Unmarshal(%s) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
