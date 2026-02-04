package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

func ServiceUnits(repoRootAbs string, includeGlobs []string, excludeGlobs []string) ([]string, error) {
	repoFS := os.DirFS(repoRootAbs)

	var matches []string
	seen := map[string]struct{}{}
	for _, pattern := range includeGlobs {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		files, err := doublestar.Glob(repoFS, pattern)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", pattern, err)
		}
		for _, f := range files {
			if !strings.HasSuffix(f, ".service") {
				continue
			}
			rel := filepath.Clean(f)
			if rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			if isExcluded(rel, excludeGlobs) {
				continue
			}
			if _, ok := seen[rel]; ok {
				continue
			}
			seen[rel] = struct{}{}
			matches = append(matches, rel)
		}
	}

	sort.Strings(matches)
	return matches, nil
}

func isExcluded(path string, excludeGlobs []string) bool {
	for _, pattern := range excludeGlobs {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		ok, err := doublestar.PathMatch(pattern, path)
		if err == nil && ok {
			return true
		}
	}
	return false
}
