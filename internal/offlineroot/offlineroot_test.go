package offlineroot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuilderCopiesServiceAndDropIns(t *testing.T) {
	repo := t.TempDir()
	serviceRel := filepath.ToSlash(filepath.Join("deploy", "systemd", "myapp.service"))
	serviceAbs := filepath.Join(repo, filepath.FromSlash(serviceRel))
	mustWrite(t, serviceAbs, "[Service]\nExecStart=/bin/true\n")

	dropInDir := serviceAbs + ".d"
	mustWrite(t, filepath.Join(dropInDir, "override.conf"), "[Service]\nNoNewPrivileges=yes\n")

	b := Builder{RepoRootAbs: repo}
	root, units, err := b.Build([]string{serviceRel})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	if len(units) != 1 {
		t.Fatalf("units len = %d, want 1", len(units))
	}

	gotService := filepath.Join(root, "etc", "systemd", "system", "myapp.service")
	if _, err := os.Stat(gotService); err != nil {
		t.Fatalf("expected service copied at %s: %v", gotService, err)
	}
	gotDropIn := filepath.Join(root, "etc", "systemd", "system", "myapp.service.d", "override.conf")
	if _, err := os.Stat(gotDropIn); err != nil {
		t.Fatalf("expected drop-in copied at %s: %v", gotDropIn, err)
	}
}

func TestBuilderDetectsCollisions(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "a", "dup.service"), "[Service]\n")
	mustWrite(t, filepath.Join(repo, "b", "dup.service"), "[Service]\n")

	b := Builder{RepoRootAbs: repo}
	_, _, err := b.Build([]string{"a/dup.service", "b/dup.service"})
	if err == nil {
		t.Fatalf("expected collision error")
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
