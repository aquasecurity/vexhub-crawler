package vexhub

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/manifest"
	"github.com/aquasecurity/vexhub-crawler/pkg/repo"
)

// GenerateIndex generates the index of the VEX Hub
func GenerateIndex(root string) error {
	slog.Info("Generating the index of the VEX Hub")
	errBuilder := oops.Code("file_walk_error").In("vexhub")
	index := repo.Index{
		UpdatedAt: time.Now(),
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		errBuilder := oops.With("path", path)
		if err != nil {
			return errBuilder.Wrap(err)
		} else if d.IsDir() || filepath.Base(path) != manifest.FileName {
			return nil
		}

		dir := filepath.Dir(path)
		m, err := manifest.Read(path)
		if err != nil {
			return errBuilder.Wrapf(err, "manifest read error")
		} else if len(m.Sources) == 0 {
			return nil
		}

		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return errBuilder.Wrapf(err, "file rel error")
		}

		// Take the first VEX document only
		index.Packages = append(index.Packages, repo.Package{
			ID:       m.ID,
			Location: filepath.Join(rel, m.Sources[0].Path),
		})

		return nil
	})
	if err != nil {
		return errBuilder.Wrap(err)
	}

	f, err := os.Create(filepath.Join(root, "index.json"))
	if err != nil {
		return errBuilder.Wrapf(err, "file write error")
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetIndent("", "   ")
	return errBuilder.Wrapf(e.Encode(index), "json encode error")
}
