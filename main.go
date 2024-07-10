package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/lmittmann/tint"
	"github.com/samber/oops"

	"github.com/aquasecurity/vex-collector/pkg/crawl"
	"github.com/aquasecurity/vex-collector/pkg/vexhub"
)

func init() {
	// set global logger
	slog.SetDefault(slog.New(tint.NewHandler(os.Stderr, nil)))
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func run() error {
	ctx := context.Background()

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

	hub, err := vexhub.Load(*vexHubDir)
	if err != nil {
		return oops.Wrapf(err, "failed to load")
	}

	if err = crawl.Packages(ctx, hub); err != nil {
		return oops.Wrapf(err, "failed to crawl packages")
	}

	return oops.Wrap(hub.GenerateIndex())
}
