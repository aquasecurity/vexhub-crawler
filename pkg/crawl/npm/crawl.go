package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/package-url/packageurl-go"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/vex"
)

const npmAPI = "https://registry.npmjs.org/"

type Response struct {
	Repository struct {
		URL string `json:"url"`
	} `json:"repository"`
}

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
		src = repoURL
	}
	if err := vex.CrawlPackage(ctx, c.rootDir, src, pkg.PURL); err != nil {
		return fmt.Errorf("failed to crawl package: %w", err)
	}
	return nil
}

func (c *Crawler) detectSrc(purl packageurl.PackageURL) (string, error) {
	pkg := path.Join(purl.Namespace, purl.Name)

	npmURL := npmAPI + pkg
	resp, err := http.Get(npmURL)
	if err != nil {
		return "", fmt.Errorf("failed to get package info: %w", err)
	}
	defer resp.Body.Close()

	var r Response
	if err = json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if r.Repository.URL == "" {
		return "", fmt.Errorf("no repository URL found")
	}

	u, err := git.NormalizeURL(r.Repository.URL)
	if err != nil {
		return "", fmt.Errorf("failed to normalize URL: %w", err)
	}
	return u.String(), nil
}
