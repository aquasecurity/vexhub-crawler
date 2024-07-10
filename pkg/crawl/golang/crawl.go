package golang

import (
	"context"
	"fmt"
	"path"
	"strings"

	"golang.org/x/tools/go/vcs"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
)

type Crawler struct{}

func NewCrawler() *Crawler {
	return &Crawler{}
}

func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (string, error) {
	purl := pkg.PURL
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
