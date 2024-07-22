package config

import (
	"os"

	"github.com/package-url/packageurl-go"
	"github.com/samber/oops"
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
	errBuilder := oops.Code("load_config_error").In("config").With("filePath", configPath)
	f, err := os.Open(configPath)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "file open error")
	}
	defer f.Close()

	var config configFile
	if err = yaml.NewDecoder(f).Decode(&config); err != nil {
		return nil, errBuilder.Wrapf(err, "failed to decode the file")
	}

	pkgs, err := parsePackages(config.Packages)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to parse packages")
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
				return nil, oops.Errorf("name is required")
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
