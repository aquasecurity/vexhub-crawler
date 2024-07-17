package golang

import (
	"context"
	"path"
	"strings"

	"github.com/samber/oops"
	"golang.org/x/tools/go/vcs"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
)

type Crawler struct{}

func NewCrawler() *Crawler {
	return &Crawler{}
}

func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (string, error) {
	errBuilder := oops.Code("crawl_error").In("golang").With("purl", pkg.PURL.String())

	purl := pkg.PURL
	importPath := path.Join(purl.Namespace, purl.Name, purl.Subpath)

	errBuilder = errBuilder.With("url", importPath)
	repoRoot, err := vcs.RepoRootForImportPath(importPath, false)
	if err != nil {
		return "", errBuilder.Wrapf(err, "failed to get repo root")
	}

	u, err := git.NormalizeURL(repoRoot.Repo)
	if err != nil {
		return "", errBuilder.Wrapf(err, "failed to normalize URL")
	}

	subPath := strings.TrimPrefix(importPath, repoRoot.Root)
	if subPath != "" {
		// cf. https://github.com/hashicorp/go-getter?tab=readme-ov-file#subdirectories
		u.Path += "/" + subPath
	}
	return u.String(), nil
}
