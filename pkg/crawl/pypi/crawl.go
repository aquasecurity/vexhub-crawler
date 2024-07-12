package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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

type Crawler struct {
	url string
}

type Option func(*Crawler)

func WithURL(url string) Option {
	return func(c *Crawler) {
		c.url = url
	}
}

func NewCrawler(opts ...Option) *Crawler {
	crawler := &Crawler{
		url: pypiAPI,
	}
	for _, opt := range opts {
		opt(crawler)
	}
	return crawler
}

func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (string, error) {
	// "pypi" type doesn't have namespace
	// cf. https://github.com/package-url/purl-spec/blob/b33dda1cf4515efa8eabbbe8e9b140950805f845/PURL-TYPES.rst#pypi
	// Default url format is `https://pypi.org/pypi/<package-name>/json`
	pypiURL, err := url.JoinPath(c.url, pkg.PURL.Name, "json")
	if err != nil {
		return "", fmt.Errorf("failed to build package url: %w", err)
	}

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
