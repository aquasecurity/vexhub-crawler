package vexhub

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/package-url/packageurl-go"
	"github.com/samber/oops"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/vex-collector/pkg/manifest"
	"github.com/aquasecurity/vex-collector/pkg/repo"
)

type Package struct {
	PURL packageurl.PackageURL
	URL  string
}

type configFile struct {
	Packages packages `yaml:"pkg"`
}

type packages map[string][]struct {
	Namespace  string `yaml:"namespace"`
	Name       string `yaml:"name"`
	Qualifiers []struct {
		Key   string `yaml:"key"`
		Value string `yaml:"value"`
	} `yaml:"qualifiers"`
	Subpath string `yaml:"subpath"`

	URL string `yaml:"url"`
}

type Hub struct {
	Root     string
	Packages []Package
}

func Load(dir string) (*Hub, error) {
	f, err := os.Open(filepath.Join(dir, "vexhub.yaml"))
	if err != nil {
		return nil, fmt.Errorf("file open error: %w", err)
	}
	defer f.Close()

	var config configFile
	if err = yaml.NewDecoder(f).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode the file: %w", err)
	}

	pkgs, err := parsePackages(config.Packages)
	if err != nil {
		return nil, fmt.Errorf("failed to parse packages: %w", err)
	}

	return &Hub{
		Root:     dir,
		Packages: pkgs,
	}, nil
}

func parsePackages(packages packages) ([]Package, error) {
	var pkgs []Package
	for pkgType, pkgList := range packages {
		for _, pkg := range pkgList {
			if pkg.Name == "" {
				return nil, fmt.Errorf("name is required")
			}

			var qs packageurl.Qualifiers
			for _, q := range pkg.Qualifiers {
				qs = append(qs, packageurl.Qualifier{
					Key:   q.Key,
					Value: q.Value,
				})
			}

			purl := packageurl.PackageURL{
				Type:       pkgType,
				Namespace:  pkg.Namespace,
				Name:       pkg.Name,
				Qualifiers: qs,
				Subpath:    pkg.Subpath,
			}
			pkgs = append(pkgs, Package{
				PURL: purl,
				URL:  pkg.URL,
			})
		}
	}
	return pkgs, nil
}

// GenerateIndex generates the index of the VEX Hub
func (h *Hub) GenerateIndex() error {
	slog.Info("Generating the index of the VEX Hub")
	errBuilder := oops.Code("file_walk_error").In("vexhub")
	index := repo.Index{
		Version: 1,
	}
	err := filepath.WalkDir(h.Root, func(path string, d os.DirEntry, err error) error {
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

		rel, err := filepath.Rel(h.Root, dir)
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

	f, err := os.Create(filepath.Join(h.Root, "index.json"))
	if err != nil {
		return errBuilder.Wrapf(err, "file write error")
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetIndent("", "   ")
	return errBuilder.Wrapf(e.Encode(index), "json encode error")
}
