package cargo

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/vex-collector/pkg/crawl/git"
	"github.com/aquasecurity/vex-collector/pkg/crawl/vex"
	"github.com/aquasecurity/vex-collector/pkg/vexhub"
	"github.com/package-url/packageurl-go"
	"net/http"
)

const cratesAPI = "https://crates.io/api/v1/crates/"

type Response struct {
	Crate struct {
		Repository string `json:"repository"`
	} `json:"crate"`
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
	rawurl := cratesAPI + purl.Name

	req, err := http.NewRequest(http.MethodGet, rawurl, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Need to set a user-agent header
	// cf. https://crates.io/data-access
	req.Header.Set("User-Agent", "aquasecurity/vex-crawler")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get package info: %w", err)
	}
	defer resp.Body.Close()

	var r Response
	if err = json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if r.Crate.Repository == "" {
		return "", fmt.Errorf("no repository URL found")
	}

	u, err := git.NormalizeURL(r.Crate.Repository)
	if err != nil {
		return "", fmt.Errorf("failed to normalize URL: %w", err)
	}
	return u.String(), nil
}
