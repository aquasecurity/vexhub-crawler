package vex

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/download"
	"github.com/aquasecurity/vexhub-crawler/pkg/manifest"
)

var (
	errPURLMismatch = fmt.Errorf("PURL does not match")
	errNoStatement  = fmt.Errorf("no statements found")
)

func CrawlPackage(ctx context.Context, vexHubDir, url string, purl packageurl.PackageURL) error {
	errBuilder := oops.In("crawl").With("purl", purl.String()).With("url", url)
	tmpDir, err := os.MkdirTemp("", "vexhub-crawler-*")
	if err != nil {
		return errBuilder.Wrapf(err, "failed to create a temporary directory")
	}
	defer os.RemoveAll(tmpDir)

	dst := filepath.Join(tmpDir, purl.Name)
	if err = download.Download(ctx, url, dst); err != nil {
		return errBuilder.Wrapf(err, "download error")
	}

	permaLink := githubPermalink(dst)
	if permaLink != nil {
		errBuilder.With("permalink", permaLink.String())
	}

	vexDir := filepath.Join(vexHubDir, "pkg", purl.Type, purl.Namespace, purl.Name, purl.Subpath)
	if purl.Type == packageurl.TypeOCI {
		name := purl.Qualifiers.Map()["repository_url"]
		vexDir = filepath.Join(vexHubDir, "pkg", purl.Type, name)
	}
	vexDir = filepath.Clean(filepath.ToSlash(vexDir))
	errBuilder = errBuilder.With("dir", vexDir)

	// Reset the directory
	if err = os.RemoveAll(vexDir); err != nil {
		return errBuilder.Wrapf(err, "failed to remove the directory")
	}
	if err = os.MkdirAll(vexDir, 0755); err != nil {
		return errBuilder.Wrapf(err, "failed to create a directory")
	}

	var found bool
	var sources []manifest.Source
	logger := slog.With(slog.String("purl", purl.String()), "url", url)
	root := filepath.Join(dst, ".vex")
	err = filepath.WalkDir(root, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return errBuilder.Wrapf(err, "failed to walk the directory")
		} else if d.IsDir() {
			return nil
		} else if !matchPath(filePath) {
			return nil
		}

		relPath, err := filepath.Rel(dst, filePath) // Relative path from the repository root, not from ".vex/"
		if err != nil {
			return errBuilder.With("file_path", filePath).Wrapf(err, "failed to get the relative path")
		}

		logger.Info("Parsing VEX file", slog.String("path", relPath))
		if err = validateVEX(filePath, purl.String()); errors.Is(err, errNoStatement) {
			return errBuilder.With("path", relPath).Wrapf(err, "no statement found")
		} else if errors.Is(err, errPURLMismatch) {
			logger.Info("PURL does not match", slog.String("path", relPath))
			return nil
		} else if err != nil {
			return errBuilder.Wrapf(err, "failed to validate VEX file")
		}

		found = true
		to := filepath.Join(vexDir, filepath.Base(filePath))
		if err = os.Rename(filePath, to); err != nil {
			return errBuilder.With("from", filePath).With("to", to).Wrapf(err, "failed to rename")
		}

		if src := fileSource(relPath, url, permaLink); src != nil {
			sources = append(sources, *src)
		}

		return nil
	})
	if err != nil {
		return errBuilder.Wrapf(err, "failed to walk the directory")
	}

	if !found {
		return errBuilder.Errorf("no VEX file found")
	}

	m := manifest.Manifest{
		ID:      purl.String(),
		Sources: sources,
	}
	if err = manifest.Write(filepath.Join(vexDir, manifest.FileName), m); err != nil {
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
			if vex.PurlMatches(purl, product.ID) {
				return nil
			}
		}
	}
	return errPURLMismatch
}

func fileSource(relPath, url string, permaLink *url.URL) *manifest.Source {
	url = strings.TrimPrefix(url, "git::")
	url = strings.TrimSuffix(url, "?depth=1")
	source := manifest.Source{
		Path: filepath.Base(relPath),
		URL:  url,
	}
	if permaLink != nil {
		l := *permaLink
		l.Path = path.Join(l.Path, relPath)
		source.URL = l.String()
	}
	return &source
}
