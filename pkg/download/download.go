package download

import (
	"context"
	"fmt"
	getter "github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
	"log/slog"
	"maps"
	"os"
)

// Download downloads the configured source to the destination.
func Download(ctx context.Context, src, dst string) error {
	slog.Info("Downloading...", slog.String("src", src))

	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get the current working directory: %w", err)
	}

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     src,
		Dst:     dst,
		Pwd:     pwd,
		Getters: maps.Clone(getter.Getters),
		Mode:    getter.ClientModeAny,
	}

	if err = client.Get(); err != nil {
		return xerrors.Errorf("download error: %w", err)
	}

	return nil
}
