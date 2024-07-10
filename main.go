package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/lmittmann/tint"
	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl"
	"github.com/aquasecurity/vexhub-crawler/pkg/vexhub"
)

func init() {
	// set global logger
	slog.SetDefault(slog.New(tint.NewHandler(os.Stderr, nil)))
}

func main() {
	if err := run(); err != nil {
		slog.Error("Fatal error")
		fmt.Printf("%+v", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	configPath := flag.String("config", "crawler.yaml", "Crawler config")
	vexHubDir := flag.String("vexhub-dir", "", "Vex Hub directory")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	if *vexHubDir == "" {
		return fmt.Errorf("--vexhub-dir is required")
	}
	if *debug {
		slog.SetDefault(slog.New(tint.NewHandler(os.Stderr, &tint.Options{
			Level: slog.LevelDebug,
		})))
	}

	c, err := config.Load(*configPath)
	if err != nil {
		return oops.Wrapf(err, "failed to load")
	}

	if err = crawl.Packages(ctx, crawl.Options{
		VEXHubDir: *vexHubDir,
		Packages:  c.Packages,
	}); err != nil {
		return oops.Wrapf(err, "failed to crawl packages")
	}

	return oops.Wrap(vexhub.GenerateIndex(*vexHubDir))
}
