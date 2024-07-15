package oci_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/oci"
)

func TestCrawler_DetectSrc(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		pkg     config.Package
		want    string
		wantErr string
	}{
		{
			name: "happy path url from config",
			dir:  filepath.Join("testdata", "url-from-config"),
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type:    packageurl.TypeOCI,
					Name:    "trivy",
					Version: "sha256:53e6715d5c67e80e629f0dfa3bd6ed2bc74bdcaa4bdbe934a5a1811a249db6b9",
				},
			},
			want: "git::https://github.com/aquasecurity/trivy.git?depth=1",
		},
		{
			name: "happy path url from manifest",
			dir:  filepath.Join("testdata", "url-from-manifest"),
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type:    packageurl.TypeOCI,
					Name:    "trivy",
					Version: "sha256:53e6715d5c67e80e629f0dfa3bd6ed2bc74bdcaa4bdbe934a5a1811a249db6b9",
				},
			},
			want: "git::https://github.com/aquasecurity/trivy.git?depth=1",
		},
		{
			name: "happy path with tag",
			dir:  filepath.Join("testdata", "url-from-config"),
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type:    packageurl.TypeOCI,
					Name:    "trivy",
					Version: "sha256:53e6715d5c67e80e629f0dfa3bd6ed2bc74bdcaa4bdbe934a5a1811a249db6b9",
					Qualifiers: []packageurl.Qualifier{
						{
							Key:   "tag",
							Value: "0.53.0",
						},
					},
				},
			},
			want: "git::https://github.com/aquasecurity/trivy.git?depth=1",
		},
		{
			name: "sad path - url no found",
			dir:  filepath.Join("testdata", "url-not-found"),
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type:    packageurl.TypeOCI,
					Name:    "trivy",
					Version: "sha256:53e6715d5c67e80e629f0dfa3bd6ed2bc74bdcaa4bdbe934a5a1811a249db6b9",
				},
			},
			wantErr: "finding image source: annotation not found",
		},
		{
			name: "sad path - image not found",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type:    packageurl.TypeOCI,
					Name:    "trivy",
					Version: "sha256:53e6715d5c67e80e629f0dfa3bd6ed2bc74bdcaa4bdbe934a5a1811a249db6b9",
					Qualifiers: []packageurl.Qualifier{
						{
							Key:   "tag",
							Value: "image-not-found",
						},
					},
				},
			},
			wantErr: "reading image",
		},
		{
			name: "sad path - config error",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type:    packageurl.TypeOCI,
					Name:    "trivy",
					Version: "sha256:53e6715d5c67e80e629f0dfa3bd6ed2bc74bdcaa4bdbe934a5a1811a249db6b9",
					Qualifiers: []packageurl.Qualifier{
						{
							Key:   "tag",
							Value: "config-error",
						},
					},
				},
			},
			wantErr: "finding image source: reading config: EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.RequestURI, "image-not-found"):
					w.WriteHeader(http.StatusNotFound)
				case strings.HasSuffix(r.RequestURI, "config-error"):
					_, err := w.Write([]byte{})
					require.NoError(t, err)
				case strings.HasPrefix(r.RequestURI, "/v2/aquasec/trivy/manifests/"):
					imageTag := "latest"
					if tag, ok := tt.pkg.PURL.Qualifiers.Map()["tag"]; ok {
						imageTag = tag
					}
					require.Contains(t, r.RequestURI, imageTag)

					http.ServeFile(w, r, filepath.Join(tt.dir, "manifest.json"))
				case strings.HasPrefix(r.RequestURI, "/v2/aquasec/trivy/blobs/"):
					http.ServeFile(w, r, filepath.Join(tt.dir, "config.json"))
				case strings.HasPrefix(r.RequestURI, "/v2/"):
					w.WriteHeader(http.StatusOK)
				}

			}))
			t.Cleanup(ts.Close)

			u, err := url.Parse(ts.URL)
			require.NoError(t, err)

			tt.pkg.PURL.Qualifiers = append(tt.pkg.PURL.Qualifiers, packageurl.Qualifier{
				Key:   "repository_url",
				Value: u.Host + "/aquasec/trivy",
			})

			crawler := oci.NewCrawler()
			got, err := crawler.DetectSrc(context.Background(), tt.pkg)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
