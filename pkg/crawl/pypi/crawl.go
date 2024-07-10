package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
)

const pypiAPI = "https://pypi.org/pypi"

type Response struct {
	Info struct {
		ProjectURLs struct {
			Source string
		} `json:"project_urls"`
	} `json:"info"`
}

type Crawler struct{}

func NewCrawler() *Crawler {
	return &Crawler{}
}

func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (string, error) {
	// "pypi" type doesn't have namespace
	// cf. https://github.com/package-url/purl-spec/blob/b33dda1cf4515efa8eabbbe8e9b140950805f845/PURL-TYPES.rst#pypi
	pypiURL := fmt.Sprintf("%s/%s/json", pypiAPI, pkg.PURL.Name)
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
