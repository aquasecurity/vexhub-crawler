package crawl

import (
	"context"
	"github.com/aquasecurity/vex-collector/pkg/crawl/cargo"
	"github.com/aquasecurity/vex-collector/pkg/crawl/golang"
	"github.com/aquasecurity/vex-collector/pkg/crawl/maven"
	"github.com/aquasecurity/vex-collector/pkg/crawl/npm"
	"github.com/aquasecurity/vex-collector/pkg/crawl/oci"
	"github.com/aquasecurity/vex-collector/pkg/crawl/pypi"
	"github.com/aquasecurity/vex-collector/pkg/vexhub"
	"github.com/package-url/packageurl-go"
	"log/slog"
)

type Crawler interface {
	Crawl(context.Context, vexhub.Package) error
}

func Packages(ctx context.Context, hub *vexhub.Hub) error {
	for _, pkg := range hub.Packages {
		var crawler Crawler
		switch pkg.PURL.Type {
		case packageurl.TypeGolang:
			crawler = golang.NewCrawler(hub.Root)
		case packageurl.TypeNPM:
			crawler = npm.NewCrawler(hub.Root)
		case packageurl.TypePyPi:
			crawler = pypi.NewCrawler(hub.Root)
		case packageurl.TypeCargo:
			crawler = cargo.NewCrawler(hub.Root)
		case packageurl.TypeMaven:
			crawler = maven.NewCrawler(hub.Root)
		case packageurl.TypeOCI:
			crawler = oci.NewCrawler(hub.Root)
		default:
			slog.Error("Unsupported package type", slog.String("type", pkg.PURL.Type))
			continue
		}
		slog.Info("Crawling package",
			slog.String("type", pkg.PURL.Type), slog.String("purl", pkg.PURL.String()))
		if err := crawler.Crawl(ctx, pkg); err != nil {
			return err
		}
	}
	return nil
}
