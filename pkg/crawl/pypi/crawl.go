package pypi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	xurl "github.com/aquasecurity/vexhub-crawler/pkg/url"
)

const pypiAPI = "https://pypi.org/pypi"

// sourceLabels are the normalized project URL labels that point to the source repository:
// the well-known "source" label followed by its aliases.
// cf. https://packaging.python.org/en/latest/specifications/well-known-project-urls/#well-known-labels
var sourceLabels = []string{"source", "repository", "sourcecode", "github"}

// labelRemovedChars are the ASCII punctuation and whitespace characters removed during label normalization.
const labelRemovedChars = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\v\f"

type Response struct {
	Info struct {
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
}

// normalizeLabel normalizes a project URL label as defined by the PyPA specification.
// cf. https://packaging.python.org/en/latest/specifications/well-known-project-urls/#label-normalization
func normalizeLabel(label string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if strings.ContainsRune(labelRemovedChars, r) {
			return -1
		}
		return r
	}, label))
}

// sourceURL returns the project URL labeled as the source repository, or an empty string if there is none.
func sourceURL(projectURLs map[string]string) string {
	// Sort labels so that the result is deterministic when several labels normalize to the same value.
	labels := make([]string, 0, len(projectURLs))
	for label := range projectURLs {
		labels = append(labels, label)
	}
	slices.Sort(labels)

	urls := make(map[string]string)
	for _, label := range labels {
		normalized := normalizeLabel(label)
		if _, ok := urls[normalized]; !ok && projectURLs[label] != "" {
			urls[normalized] = projectURLs[label]
		}
	}

	for _, label := range sourceLabels {
		if u, ok := urls[label]; ok {
			return u
		}
	}
	return ""
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

func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (*xurl.URL, error) {
	errBuilder := oops.Code("crawl_error").In("pypi").With("purl", pkg.PURL.String())
	// "pypi" type doesn't have namespace
	// cf. https://github.com/package-url/purl-spec/blob/b33dda1cf4515efa8eabbbe8e9b140950805f845/PURL-TYPES.rst#pypi
	// Default url format is `https://pypi.org/pypi/<package-name>/json`
	pypiURL, err := url.JoinPath(c.url, pkg.PURL.Name, "json")
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to build package url")
	}

	errBuilder = errBuilder.With("url", pypiURL)
	resp, err := http.Get(pypiURL)
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

	src := sourceURL(r.Info.ProjectURLs)
	if src == "" {
		return nil, errBuilder.Errorf("source URL not found")
	}

	u, err := xurl.Parse(src)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to normalize URL")
	}
	return u, nil
}
