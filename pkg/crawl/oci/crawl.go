package oci

import (
	"context"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/samber/oops"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/url"
)

const imageSourceAnnotation = "org.opencontainers.image.source"

type Crawler struct{}

func NewCrawler() *Crawler {
	return &Crawler{}
}

func (c *Crawler) DetectSrc(_ context.Context, pkg config.Package) (*url.URL, error) {
	errBuilder := oops.Code("crawl_error").In("oci").With("purl", pkg.PURL.String())
	qs := pkg.PURL.Qualifiers.Map()
	repositoryURL, ok := qs["repository_url"]
	if !ok {
		return nil, oops.Errorf("repository_url not found")
	}
	tag, ok := qs["tag"]
	if !ok {
		tag = "latest"
	}

	refStr := repositoryURL + ":" + tag
	errBuilder = errBuilder.With("ref", refStr)
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "parsing reference")
	}

	img, err := remote.Image(ref)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "reading image")
	}

	src, err := c.findImageSource(img)
	if err != nil {
		return nil, errBuilder.Wrapf(err, "finding image source")
	}

	u, err := url.Parse(src)
	if err != nil {
		return nil, errBuilder.With("url", src).Wrapf(err, "normalizing URL")
	}

	return u, nil
}

func (c *Crawler) findImageSource(img v1.Image) (string, error) {
	// First, try labels in config
	cfg, err := img.ConfigFile()
	if err != nil {
		return "", oops.Wrapf(err, "reading config")
	}

	src, ok := cfg.Config.Labels[imageSourceAnnotation]
	if ok {
		slog.Info("Found image label", slog.String("label", imageSourceAnnotation),
			slog.String("value", src))
		return src, nil
	}

	// Next, try annotations in manifest
	m, err := img.Manifest()
	if err != nil {
		return "", oops.Wrapf(err, "reading manifest")
	}

	src, ok = m.Annotations[imageSourceAnnotation]
	if ok {
		slog.Info("Found image annotation", slog.String("annotation", imageSourceAnnotation),
			slog.String("value", src))
		return src, nil
	}

	return "", oops.With("annotation", imageSourceAnnotation).Errorf("annotation not found")
}
