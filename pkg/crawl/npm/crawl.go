package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
	"net/http"
	"net/url"
)

const npmAPI = "https://registry.npmjs.org/"

type Response struct {
	Repository struct {
		URL string `json:"url"`
	} `json:"repository"`
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
		url: npmAPI,
	}
	for _, opt := range opts {
		opt(crawler)
	}
	return crawler
}

func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (string, error) {
	npmURL, err := url.JoinPath(c.url, pkg.PURL.Namespace, pkg.PURL.Name)
	if err != nil {
		return "", fmt.Errorf("failed to build package url: %w", err)
	}

	resp, err := http.Get(npmURL)
	if err != nil {
		return "", fmt.Errorf("failed to get package info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get package info: %s", resp.Status)
	}

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
