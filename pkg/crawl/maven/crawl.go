package maven

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/vex"
)

const defaultRepo = "https://repo.maven.apache.org/maven2"

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

// detectSrc detects the source repository URL of the package.
// It fetches the latest version and POM file to extract the repository URL
// as we didn't find a way to get the repository URL directly from the metadata.
func (c *Crawler) detectSrc(purl packageurl.PackageURL) (string, error) {
	repoURL := defaultRepo
	if v, ok := purl.Qualifiers.Map()["repository_url"]; ok {
		repoURL = v
	}

	baseURL, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse repository URL: %w", err)
	}

	pkg := path.Join(purl.Namespace, purl.Name)
	pkg = strings.ReplaceAll(pkg, ".", "/")
	baseURL.Path = path.Join(baseURL.Path, pkg)

	latest, err := c.fetchLatestVersion(baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch the latest version: %w", err)
	}
	slog.Info("Latest version found",
		slog.String("purl", purl.String()), slog.String("version", latest))

	pom, err := c.fetchPOM(baseURL, purl.Name, latest)
	if err != nil {
		return "", fmt.Errorf("failed to fetch POM: %w", err)
	}

	srcURL, err := c.extractScrURL(pom)
	if err != nil {
		return "", fmt.Errorf("failed to extract repository URL: %w", err)
	}

	u, err := git.NormalizeURL(srcURL)
	if err != nil {
		return "", fmt.Errorf("failed to normalize URL: %w", err)
	}

	return u.String(), nil
}

func (c *Crawler) fetchLatestVersion(baseURL *url.URL) (string, error) {
	metaURL := *baseURL
	metaURL.Path = path.Join(metaURL.Path, "maven-metadata.xml")

	resp, err := http.Get(metaURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to get package info: %w", err)
	}
	defer resp.Body.Close()

	var metadata Metadata
	if err = xml.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if metadata.Versioning.Latest == "" {
		return "", fmt.Errorf("no latest version found")
	}

	return metadata.Versioning.Latest, nil
}

func (c *Crawler) fetchPOM(baseURL *url.URL, name, latest string) (*POM, error) {
	pomURL := *baseURL
	pomURL.Path = path.Join(pomURL.Path, latest, fmt.Sprintf("%s-%s.pom", name, latest))

	resp, err := http.Get(pomURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get package info: %w", err)
	}
	defer resp.Body.Close()

	var pom POM
	if err = xml.NewDecoder(resp.Body).Decode(&pom); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
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

	return "", fmt.Errorf("no repository URL found")
}
