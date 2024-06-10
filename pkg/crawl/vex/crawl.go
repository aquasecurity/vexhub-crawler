package vex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/vex-collector/pkg/download"
	"github.com/go-git/go-git/v5"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var (
	errPURLMismatch = fmt.Errorf("PURL does not match")
	errNoStatement  = fmt.Errorf("no statements found")
)

type Source struct {
	Path string `json:"path"`
	URL  string `json:"url"`
}

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

	permaLink := githubPermalink(dst)

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
	var sources []Source
	logger := slog.With("purl", purl.String(), "url", url)
	err = filepath.WalkDir(tmpDir, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk the directory: %w", err)
		} else if d.IsDir() {
			if filepath.Base(filePath) == "testdata" || filepath.Base(filePath) == "test" {
				slog.Debug("Skipping test directory", slog.String("path", filePath))
				return filepath.SkipDir
			}
			return nil
		} else if !matchPath(filePath) {
			return nil
		}

		logger.Info("Parsing VEX file", slog.String("path", filePath))
		if err = validateVEX(filePath, purl.String()); errors.Is(err, errNoStatement) {
			logger.Error("No statements found", slog.String("path", filePath))
			return nil
		} else if errors.Is(err, errPURLMismatch) {
			logger.Error("PURL does not match", slog.String("path", filePath))
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to validate VEX file: %w", err)
		}

		found = true
		if err = os.Rename(filePath, filepath.Join(vexDir, filepath.Base(filePath))); err != nil {
			return fmt.Errorf("failed to move the file: %w", err)
		}

		if src := fileSource(dst, filePath, url, permaLink); src != nil {
			sources = append(sources, *src)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk the directory: %w", err)
	}

	if !found {
		logger.Warn("No VEX file found")
	}
	if err = writeSources(sources, vexDir); err != nil {
		return fmt.Errorf("failed to write sources: %w", err)
	}

	return nil
}

func githubPermalink(repoDir string) *url.URL {
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return nil
	}

	r, err := repo.Remote("origin")
	if err != nil {
		return nil
	}

	urls := r.Config().URLs
	if len(urls) == 0 {
		return nil
	}
	u, err := url.Parse(urls[0])
	if err != nil || u.Host != "github.com" {
		return nil
	}
	p, _, ok := strings.Cut(u.Path, ".git")
	if !ok {
		return nil
	}
	head, err := repo.Head()
	if err != nil {
		return nil
	}

	// e.g. https://github.com/aquasecurity/vextest/blob/ed76fc6c0e8e56318ce3148bd7bd938aad41491c/
	u.Path = path.Join(p, "blob", head.Hash().String())

	u.Scheme = "https"
	u.User = nil
	u.RawQuery = ""
	return u
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

func fileSource(root, filePath, url string, permaLink *url.URL) *Source {
	relPath, err := filepath.Rel(root, filePath)
	if err != nil {
		slog.Error("Failed to get the relative path", slog.String("path", filePath), slog.Any("err", err))
		return nil
	}

	source := Source{
		Path: filepath.Base(filePath),
		URL:  url,
	}
	if permaLink != nil {
		l := *permaLink
		l.Path = path.Join(l.Path, relPath)
		source.URL = l.String()
	}
	return &source
}

func writeSources(sources []Source, dir string) error {
	f, err := os.Create(filepath.Join(dir, "sources.json"))
	if err != nil {
		return fmt.Errorf("failed to create sources file: %w", err)
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetIndent("", "    ")
	if err = e.Encode(sources); err != nil {
		return fmt.Errorf("JSON encode error: %w", err)
	}
	return nil
}
