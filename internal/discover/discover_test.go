package discover

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestServiceUnits(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "deploy/systemd/a.service"), "[Service]\nExecStart=/bin/true\n")
	mustWrite(t, filepath.Join(repo, "deploy/systemd/b.socket"), "[Socket]\nListenStream=1234\n")
	mustWrite(t, filepath.Join(repo, "deploy/systemd/nested/c.service"), "[Service]\nExecStart=/bin/true\n")

	got, err := ServiceUnits(repo, []string{"deploy/systemd/**/*.service"}, nil)
	if err != nil {
		t.Fatalf("ServiceUnits() error = %v", err)
	}
	want := []string{
		"deploy/systemd/a.service",
		"deploy/systemd/nested/c.service",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ServiceUnits() = %#v, want %#v", got, want)
	}
}

func TestServiceUnitsExclude(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "deploy/systemd/a.service"), "[Service]\n")
	mustWrite(t, filepath.Join(repo, "deploy/systemd/skip.service"), "[Service]\n")

	got, err := ServiceUnits(repo, []string{"deploy/systemd/*.service"}, []string{"**/skip.service"})
	if err != nil {
		t.Fatalf("ServiceUnits() error = %v", err)
	}
	want := []string{"deploy/systemd/a.service"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ServiceUnits() = %#v, want %#v", got, want)
	}
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
