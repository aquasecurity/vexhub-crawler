package vexhub

import (
	"fmt"
	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

type Hub struct {
	Root     string
	Packages []Package
}

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
