package vex

import (
	"context"
	"errors"
	"fmt"
	"github.com/aquasecurity/vex-collector/pkg/download"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

var (
	errPURLMismatch = fmt.Errorf("PURL does not match")
	errNoStatement  = fmt.Errorf("no statements found")
)

func CrawlPackage(ctx context.Context, vexHubDir, url string, purl packageurl.PackageURL) error {
	tmpDir, err := os.MkdirTemp("", "vexhub-crawler-*")
	if err != nil {
		return fmt.Errorf("failed to create a temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dst := filepath.Join(tmpDir, purl.Name)
	if err = download.Download(ctx, url, dst); err != nil {
		return fmt.Errorf("download error: %w", err)
	}

	vexDir := filepath.Join(vexHubDir, "pkg", purl.Type, purl.Namespace, purl.Name, purl.Subpath)
	vexDir = filepath.Clean(filepath.ToSlash(vexDir))

	// Reset the directory
	if err = os.RemoveAll(vexDir); err != nil {
		return fmt.Errorf("failed to remove the directory: %w", err)
	}
	if err = os.MkdirAll(vexDir, 0755); err != nil {
		return fmt.Errorf("failed to create a directory: %w", err)
	}

	var found bool
	logger := slog.With("purl", purl.String(), "url", url)
	err = filepath.WalkDir(tmpDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk the directory: %w", err)
		} else if d.IsDir() {
			if filepath.Base(path) == "testdata" || filepath.Base(path) == "test" {
				slog.Debug("Skipping test directory", slog.String("path", path))
				return filepath.SkipDir
			}
			return nil
		} else if !matchPath(path) {
			return nil
		}

		logger.Info("Parsing VEX file", slog.String("path", path))
		if err = validateVEX(path, purl.String()); errors.Is(err, errNoStatement) {
			logger.Error("No statements found", slog.String("path", path))
			return nil
		} else if errors.Is(err, errPURLMismatch) {
			logger.Error("PURL does not match", slog.String("path", path))
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to validate VEX file: %w", err)
		}

		found = true
		if err = os.Rename(path, filepath.Join(vexDir, filepath.Base(path))); err != nil {
			return fmt.Errorf("failed to move the file: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk the directory: %w", err)
	}

	if !found {
		logger.Warn("No VEX file found")
	}
	return nil
}

func matchPath(path string) bool {
	path = filepath.Base(path)
	if path == "openvex.json" || path == "vex.json" ||
		strings.HasSuffix(path, ".openvex.json") || strings.HasSuffix(path, ".vex.json") {
		return true
	}
	return false
}

func validateVEX(path, purl string) error {
	v, err := vex.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open VEX file: %w", err)
	} else if len(v.Statements) == 0 {
		return errNoStatement
	}
	for _, statement := range v.Statements {
		for _, product := range statement.Products {
			if match := vex.PurlMatches(purl, product.ID); !match {
				return errPURLMismatch
			}
		}
	}
	return nil
}
