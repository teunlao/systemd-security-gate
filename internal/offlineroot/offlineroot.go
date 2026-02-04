package offlineroot

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/teunlao/systemd-security-gate/internal/model"
)

type Builder struct {
	RepoRootAbs string
}

func (b Builder) Build(repoRelServicePaths []string) (root string, units []model.UnitFile, err error) {
	if b.RepoRootAbs == "" {
		return "", nil, fmt.Errorf("RepoRootAbs is required")
	}

	root, err = os.MkdirTemp("", "ssg-root-*")
	if err != nil {
		return "", nil, fmt.Errorf("mkdtemp: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(root)
		}
	}()

	unitDir := filepath.Join(root, "etc", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return "", nil, fmt.Errorf("mkdir %s: %w", unitDir, err)
	}

	seenUnitNames := map[string]string{}
	for _, rel := range repoRelServicePaths {
		unitName := filepath.Base(rel)
		if prev, ok := seenUnitNames[unitName]; ok {
			return "", nil, fmt.Errorf("unit name collision for %q: %q and %q (rename or narrow --paths)", unitName, prev, rel)
		}
		seenUnitNames[unitName] = rel

		src := filepath.Join(b.RepoRootAbs, rel)
		dst := filepath.Join(unitDir, unitName)
		if err := copyFile(src, dst); err != nil {
			return "", nil, err
		}

		units = append(units, model.UnitFile{
			UnitName:    unitName,
			RepoRelPath: filepath.ToSlash(rel),
		})

		if err := b.copyDropIns(rel, unitDir); err != nil {
			return "", nil, err
		}
	}

	sort.SliceStable(units, func(i, j int) bool { return units[i].UnitName < units[j].UnitName })
	return root, units, nil
}

func (b Builder) copyDropIns(repoRelServicePath string, unitDir string) error {
	unitName := filepath.Base(repoRelServicePath)
	dropInDirRel := repoRelServicePath + ".d"
	dropInDirAbs := filepath.Join(b.RepoRootAbs, dropInDirRel)

	entries, err := os.ReadDir(dropInDirAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read drop-in dir %s: %w", dropInDirRel, err)
	}

	dstDir := filepath.Join(unitDir, unitName+".d")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("mkdir drop-in dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".conf" {
			continue
		}
		src := filepath.Join(dropInDirAbs, e.Name())
		dst := filepath.Join(dstDir, e.Name())
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer func() { _ = out.Close() }()

	if _, err := out.ReadFrom(in); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}
