package cargo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
)

const cratesAPI = "https://crates.io/api/v1/crates/"

type Response struct {
	Crate struct {
		Repository string `json:"repository"`
	} `json:"crate"`
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
		url: cratesAPI,
	}
	for _, opt := range opts {
		opt(crawler)
	}
	return crawler
}
func (c *Crawler) DetectSrc(ctx context.Context, pkg config.Package) (string, error) {
	errBuilder := oops.Code("crawl_error").In("cargo").With("purl", pkg.PURL.String())
	// Cargo doesn't use `namespace`
	// cf. https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#cargo
	rawurl, err := url.JoinPath(c.url, pkg.PURL.Name)
	if err != nil {
		return "", errBuilder.Wrapf(err, "failed to build url")
	}

	errBuilder = errBuilder.With("url", rawurl)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return "", errBuilder.Wrapf(err, "failed to create request")
	}

	// Need to set a user-agent header
	// cf. https://crates.io/data-access
	req.Header.Set("User-Agent", "aquasecurity/vex-crawler")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", errBuilder.Wrapf(err, "failed to get package info")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errBuilder.Errorf("failed to get package info: %s", resp.Status)
	}

	var r Response
	if err = json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", errBuilder.Wrapf(err, "failed to decode response")
	}

	if r.Crate.Repository == "" {
		return "", errBuilder.Errorf("no repository URL found")
	}

	u, err := git.NormalizeURL(r.Crate.Repository)
	if err != nil {
		return "", errBuilder.Wrapf(err, "failed to normalize URL")
	}
	return u.String(), nil
}
