package oci

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/package-url/packageurl-go"
	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/vex"
)

const imageSourceAnnotation = "org.opencontainers.image.source"

type Crawler struct {
	rootDir string
}

func NewCrawler(rootDir string) *Crawler {
	return &Crawler{rootDir: rootDir}
}

func (c *Crawler) Crawl(ctx context.Context, pkg config.Package) error {
	src := pkg.URL
	if src == "" {
		repoURL, err := c.detectSrc(pkg.PURL)
		if err != nil {
			return fmt.Errorf("failed to detect source: %w", err)
		}
		src = repoURL
	}
	if err := vex.CrawlPackage(ctx, c.rootDir, src, pkg.PURL); err != nil {
		return oops.Wrapf(err, "failed to crawl package: %w")
	}
	return nil
}

func (c *Crawler) detectSrc(purl packageurl.PackageURL) (string, error) {
	qs := purl.Qualifiers.Map()
	repositoryURL, ok := qs["repository_url"]
	if !ok {
		return "", fmt.Errorf("repository_url not found in %s", purl.String())
	}
	tag, ok := qs["tag"]
	if !ok {
		tag = "latest"
	}

	refStr := repositoryURL + ":" + tag
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return "", fmt.Errorf("parsing reference %q: %v", refStr, err)
	}

	img, err := remote.Image(ref)
	if err != nil {
		return "", fmt.Errorf("reading image %q: %v", refStr, err)
	}

	src, err := c.findImageSource(refStr, img)
	if err != nil {
		return "", fmt.Errorf("finding image source: %w", err)
	}

	u, err := git.NormalizeURL(src)
	if err != nil {
		return "", fmt.Errorf("normalizing URL %q: %v", src, err)
	}

	return u.String(), nil
}

func (c *Crawler) findImageSource(ref string, img v1.Image) (string, error) {
	// First, try labels in config
	cfg, err := img.ConfigFile()
	if err != nil {
		return "", fmt.Errorf("reading config %q: %v", ref, err)
	}

	src, ok := cfg.Config.Labels[imageSourceAnnotation]
	if ok {
		slog.Info("Found an image label", slog.String("label", imageSourceAnnotation),
			slog.String("value", src))
		return src, nil
	}

	// Next, try annotations in manifest
	m, err := img.Manifest()
	if err != nil {
		return "", fmt.Errorf("reading manifest %q: %v", ref, err)
	}

	src, ok = m.Annotations[imageSourceAnnotation]
	if ok {
		slog.Info("Found an image annotation", slog.String("annotation", imageSourceAnnotation),
			slog.String("value", src))
		return src, nil
	}

	return "", fmt.Errorf("%s not found in %s", imageSourceAnnotation, ref)
}
