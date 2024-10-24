package maven

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/url"
)

const mavenRepo = "https://repo.maven.apache.org/maven2"

// Metadata represents maven-metadata.xml
type Metadata struct {
	Versioning Versioning `xml:"versioning"`
}

type Versioning struct {
	Latest string `xml:"latest"`
}

// POM represents pom.xml
type POM struct {
	XMLName xml.Name `xml:"project"`
	SCM     Scm      `xml:"scm"`
	URL     string   `xml:"url"`
}

type Scm struct {
	URL string `xml:"url"`
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
		url: mavenRepo,
	}
	for _, opt := range opts {
		opt(crawler)
	}
	return crawler
}

// DetectSrc detects the source repository URL of the package.
// It fetches the latest version and POM file to extract the repository URL
// as we didn't find a way to get the repository URL directly from the metadata.
func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (*url.URL, error) {
	errBuilder := oops.Code("crawl_error").In("maven").With("purl", pkg.PURL.String())

	purl := pkg.PURL

	repoURL := c.url
	if v, ok := purl.Qualifiers.Map()["repository_url"]; ok {
		repoURL = v
	}

	baseURL, err := url.Parse(repoURL)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to parse repository URL")
	}

	// GroupID (purl.Name) can contain `.`.
	// e.g. pkg:maven/ai.catboost/catboost-spark-aggregate_2.11@1.2.5 => https://repo.maven.apache.org/maven2/ai/catboost/catboost-spark-aggregate_2.11/1.2.5/
	namespace := strings.ReplaceAll(purl.Namespace, ".", "/")
	baseURL.Path = path.Join(baseURL.Path, namespace, purl.Name)

	latest, err := c.fetchLatestVersion(baseURL)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to fetch the latest version")
	}
	slog.Info(
		"Latest version found",
		slog.String("purl", purl.String()), slog.String("version", latest),
	)

	pom, err := c.fetchPOM(baseURL, purl.Name, latest)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to fetch POM")
	}

	srcURL, err := c.extractScrURL(pom)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to extract repository URL")
	}

	u, err := url.Parse(srcURL)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to normalize URL")
	}

	return u, nil
}

func (c *Crawler) fetchLatestVersion(baseURL *url.URL) (string, error) {
	metaURL := *baseURL.URL
	metaURL.Path = path.Join(metaURL.Path, "maven-metadata.xml")

	errBuilder := oops.Code("fetch_latest_version_error").With("metadata url", metaURL.String())

	resp, err := http.Get(metaURL.String())
	if err != nil {
		return "", errBuilder.Wrapf(err, "failed to get artifact metadata")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errBuilder.Errorf("failed to get artifact metadata: %s", resp.Status)
	}

	var metadata Metadata
	if err = xml.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return "", errBuilder.Wrapf(err, "failed to decode response")
	}

	if metadata.Versioning.Latest == "" {
		return "", errBuilder.Errorf("no latest version found")
	}

	return metadata.Versioning.Latest, nil
}

func (c *Crawler) fetchPOM(baseURL *url.URL, name, latest string) (*POM, error) {
	pomURL := *baseURL.URL
	pomURL.Path = path.Join(pomURL.Path, latest, fmt.Sprintf("%s-%s.pom", name, latest))

	errBuilder := oops.Code("fetch_pom_error").With("pom url", pomURL.String())
	resp, err := http.Get(pomURL.String())
	if err != nil {
		return nil, errBuilder.Wrapf(err, "failed to get package info")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errBuilder.Errorf("failed to get pom file: %s", resp.Status)
	}

	var pom POM
	if err = xml.NewDecoder(resp.Body).Decode(&pom); err != nil {
		return nil, errBuilder.Wrapf(err, "failed to decode response")
	}
	return &pom, nil
}

func (c *Crawler) extractScrURL(pom *POM) (string, error) {
	if pom.SCM.URL != "" {
		return pom.SCM.URL, nil
	}

	if pom.URL != "" {
		return pom.URL, nil
	}

	return "", oops.Errorf("no repository URL found")
}
