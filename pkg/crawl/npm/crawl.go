package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	xurl "github.com/aquasecurity/vexhub-crawler/pkg/url"
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

func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (*xurl.URL, error) {
	errBuilder := oops.Code("crawl_error").In("npm").With("purl", pkg.PURL.String())

	npmURL, err := url.JoinPath(c.url, pkg.PURL.Namespace, pkg.PURL.Name)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to build package url")
	}

	errBuilder = errBuilder.With("url", npmURL)
	resp, err := http.Get(npmURL)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to get package info")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errBuilder.Errorf("failed to get package info: %s", resp.Status)
	}

	var r Response
	if err = json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, errBuilder.Wrapf(err, "failed to decode response")
	}

	if r.Repository.URL == "" {
		return nil, errBuilder.Errorf("no repository URL found")
	}

	u, err := xurl.Parse(r.Repository.URL)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to normalize URL")
	}
	return u, nil
}
