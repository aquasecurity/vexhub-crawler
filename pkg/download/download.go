package download

import (
	"context"
	"log/slog"
	"maps"
	"os"

	"github.com/hashicorp/go-getter"
	"github.com/samber/oops"
)

// Download downloads the configured source to the destination.
func Download(ctx context.Context, src, dst string) error {
	slog.Info("Downloading...", slog.String("src", src))
	errBuilder := oops.Code("download_error").In("download").With("src", src).With("dst", dst)

	pwd, err := os.Getwd()
	if err != nil {
		return errBuilder.Wrapf(err, "failed to get the current working directory")
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
		return errBuilder.Wrapf(err, "download error")
	}

	return nil
}
