package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aquasecurity/vex-collector/pkg/crawl"
	"github.com/aquasecurity/vex-collector/pkg/vexhub"
	"github.com/lmittmann/tint"
	"log/slog"
	"os"
)

func init() {
	// set global logger
	slog.SetDefault(slog.New(tint.NewHandler(os.Stderr, nil)))
}

func main() {
	if err := run(); err != nil {
		slog.Error("Unexpected error", slog.Any("err", err))
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
		return fmt.Errorf("failed to load sources: %w", err)
	}

	if err = crawl.Packages(ctx, hub); err != nil {
		return fmt.Errorf("failed to crawl packages: %w", err)
	}

	return nil
}
