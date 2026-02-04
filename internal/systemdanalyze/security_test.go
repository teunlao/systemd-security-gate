package systemdanalyze

import "testing"

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
