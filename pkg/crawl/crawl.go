package crawl

import (
	"context"
	"log/slog"

	"github.com/package-url/packageurl-go"
	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/cargo"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/golang"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/maven"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/npm"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/oci"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/pypi"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/vex"
)

type Options struct {
	VEXHubDir string
	Packages  []config.Package
	Strict    bool
}

type Crawler interface {
	DetectSrc(context.Context, config.Package) (string, error)
}

func Packages(ctx context.Context, opts Options) error {
	for _, pkg := range opts.Packages {
		logger := slog.With(slog.String("type", pkg.PURL.Type), slog.String("purl", pkg.PURL.String()))
		logger.Info("Crawling package...")
		if err := crawlPackage(ctx, opts.VEXHubDir, pkg); err != nil {
			if opts.Strict {
				return oops.Wrapf(err, "strict")
			}
			logger.Warn(err.Error(), slog.Any("error", err))
		}
	}
	return nil
}

func crawlPackage(ctx context.Context, vexHubDir string, pkg config.Package) error {
	errBuilder := oops.Code("crawl_package").With("type", pkg.PURL.Type).With("purl", pkg.PURL.String())

	var crawler Crawler
	switch pkg.PURL.Type {
	case packageurl.TypeCargo:
		crawler = cargo.NewCrawler()
	case packageurl.TypeGolang:
		crawler = golang.NewCrawler()
	case packageurl.TypeMaven:
		crawler = maven.NewCrawler()
	case packageurl.TypeNPM:
		crawler = npm.NewCrawler()
	case packageurl.TypePyPi:
		crawler = pypi.NewCrawler()
	case packageurl.TypeOCI:
		crawler = oci.NewCrawler()
	default:
		return oops.Errorf("unsupported package type: %s", pkg.PURL.Type)
	}

	src := pkg.URL
	if src == "" {
		detected, err := crawler.DetectSrc(ctx, pkg)
		if err != nil {
			return errBuilder.Wrapf(err, "failed to detect source repository")
		}
		src = detected
	}

	if err := vex.CrawlPackage(ctx, vexHubDir, src, pkg.PURL); err != nil {
		return errBuilder.Wrapf(err, "failed to crawl package")
	}
	return nil
}
