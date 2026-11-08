package ext

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

// bundled holds the example extensions shipped inside the binary. They are
// written into the extensions directory on first run so there is something to
// read and enable, but they are never overwritten once present, so edits
// survive upgrades.
//
//go:embed examples
var bundled embed.FS

func (m *Manager) extractExamples() {
	sub, err := fs.Sub(bundled, "examples")
	if err != nil {
		return
	}
	tops, err := fs.ReadDir(sub, ".")
	if err != nil {
		return
	}
	for _, top := range tops {
		if !top.IsDir() {
			continue
		}
		dest := filepath.Join(m.dir, top.Name())
		if _, err := os.Stat(dest); err == nil {
			continue // already present; never clobber the user's copy
		}
		fs.WalkDir(sub, top.Name(), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			target := filepath.Join(m.dir, filepath.FromSlash(p))
			if d.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			data, err := fs.ReadFile(sub, p)
			if err != nil {
				return nil
			}
			return os.WriteFile(target, data, 0o644)
		})
	}
}
