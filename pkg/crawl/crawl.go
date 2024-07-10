package crawl

import (
	"context"
	"log/slog"

	"github.com/package-url/packageurl-go"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/cargo"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/golang"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/maven"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/npm"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/oci"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/pypi"
)

type Options struct {
	VEXHubDir string
	Packages  []config.Package
	Strict    bool
}

type Crawler interface {
	Crawl(context.Context, config.Package) error
}

func Packages(ctx context.Context, opts Options) error {
	for _, pkg := range opts.Packages {
		var crawler Crawler
		switch pkg.PURL.Type {
		case packageurl.TypeGolang:
			crawler = golang.NewCrawler(opts.VEXHubDir)
		case packageurl.TypeNPM:
			crawler = npm.NewCrawler(opts.VEXHubDir)
		case packageurl.TypePyPi:
			crawler = pypi.NewCrawler(opts.VEXHubDir)
		case packageurl.TypeCargo:
			crawler = cargo.NewCrawler(opts.VEXHubDir)
		case packageurl.TypeMaven:
			crawler = maven.NewCrawler(opts.VEXHubDir)
		case packageurl.TypeOCI:
			crawler = oci.NewCrawler(opts.VEXHubDir)
		default:
			slog.Error("Unsupported package type", slog.String("type", pkg.PURL.Type))
			continue
		}
		logger := slog.With(slog.String("type", pkg.PURL.Type), slog.String("purl", pkg.PURL.String()))
		logger.Info("Crawling package")
		if err := crawler.Crawl(ctx, pkg); err != nil {
			if opts.Strict {
				return err
			}
			logger.Warn(err.Error(), slog.Any("error", err))
		}
	}
	return nil
}
