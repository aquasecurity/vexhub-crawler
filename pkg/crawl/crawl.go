package crawl

import (
	"context"
	"github.com/aquasecurity/vex-collector/pkg/vexhub"
	"log/slog"
)

type Crawler interface {
	Crawl(context.Context, vexhub.Package) error
}

func Packages(ctx context.Context, hub *vexhub.Hub) error {
	for _, pkg := range hub.Packages {
		var crawler Crawler
		switch pkg.PURL.Type {
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
