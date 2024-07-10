package cargo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
)

const cratesAPI = "https://crates.io/api/v1/crates/"

type Response struct {
	Crate struct {
		Repository string `json:"repository"`
	} `json:"crate"`
}

type Crawler struct{}

func NewCrawler() *Crawler {
	return &Crawler{}
}

func (c *Crawler) DetectSrc(ctx context.Context, pkg config.Package) (string, error) {
	rawurl := cratesAPI + pkg.PURL.Name

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
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
