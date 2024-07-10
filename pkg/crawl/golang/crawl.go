package golang

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/vex"

	"github.com/package-url/packageurl-go"
	"golang.org/x/tools/go/vcs"
)

type Crawler struct {
	rootDir string
}

func NewCrawler(rootDir string) *Crawler {
	return &Crawler{rootDir: rootDir}
}

func (c *Crawler) Crawl(ctx context.Context, pkg config.Package) error {
	src := pkg.URL
	if src == "" {
		repoURL, err := c.detectSrc(pkg.PURL)
		if err != nil {
			return fmt.Errorf("failed to detect source: %w", err)
		}
		repoURL = strings.ReplaceAll(repoURL, "git::https://", "git::ssh://git@") // TODO: delete
		src = repoURL
	}
	if err := vex.CrawlPackage(ctx, c.rootDir, src, pkg.PURL); err != nil {
		return fmt.Errorf("failed to crawl package: %w", err)
	}
	return nil
}

func (c *Crawler) detectSrc(purl packageurl.PackageURL) (string, error) {
	importPath := path.Join(purl.Namespace, purl.Name, purl.Subpath)

	repoRoot, err := vcs.RepoRootForImportPath(importPath, false)
	if err != nil {
		return "", fmt.Errorf("failed to get repo root: %w", err)
	}

	u, err := git.NormalizeURL(repoRoot.Repo)
	if err != nil {
		return "", fmt.Errorf("failed to normalize URL: %w", err)
	}

	subPath := strings.TrimPrefix(importPath, repoRoot.Root)
	if subPath != "" {
		// cf. https://github.com/hashicorp/go-getter?tab=readme-ov-file#subdirectories
		u.Path += "/" + subPath
	}
	return u.String(), nil
}
