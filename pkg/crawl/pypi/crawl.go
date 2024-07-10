package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/package-url/packageurl-go"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/vex"
)

const pypiAPI = "https://pypi.org/pypi"

type Response struct {
	Info struct {
		ProjectURLs struct {
			Source string
		} `json:"project_urls"`
	} `json:"info"`
}

type Crawler struct {
	rootDir string
}

func NewCrawler(rootDir string) *Crawler {
	return &Crawler{rootDir: rootDir}
}

func (c *Crawler) Crawl(ctx context.Context, pkg vexhub.Package) error {
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
	pypiURL := fmt.Sprintf("%s/%s/json", pypiAPI, purl.Name)
	resp, err := http.Get(pypiURL)
	if err != nil {
		return "", fmt.Errorf("failed to get package info: %w", err)
	}
	defer resp.Body.Close()

	var r Response
	if err = json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if r.Info.ProjectURLs.Source == "" {
		return "", fmt.Errorf("source URL not found")
	}

	u, err := git.NormalizeURL(r.Info.ProjectURLs.Source)
	if err != nil {
		return "", fmt.Errorf("failed to normalize URL: %w", err)
	}
	return u.String(), nil
}
