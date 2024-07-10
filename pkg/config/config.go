package config

import (
	"fmt"
	"os"

	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
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

type Config struct {
	Packages []Package
}

func Load(configPath string) (*Config, error) {
	f, err := os.Open(configPath)
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

	return &Config{
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
