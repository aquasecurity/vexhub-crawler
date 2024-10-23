package pypi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/pypi"
)

func TestCrawler_DetectSrc(t *testing.T) {
	tests := []struct {
		name    string
		pkg     config.Package
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypePyPi,
					Name: "flask",
				},
			},
			want: "https://github.com/pallets/flask/",
		},
		{
			name: "sad path when response file doesn't contain source url",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypePyPi,
					Name: "no-url",
				},
			},
			wantErr: "source URL not found",
		},
		{
			name: "sad path with bad response json",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypePyPi,
					Name: "bad",
				},
			},
			wantErr: "failed to decode response",
		},
		{
			name: "sad path with missed package",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypePyPi,
					Name: "missed",
				},
			},
			wantErr: "failed to get package info: 404 Not Found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := http.FileServer(http.Dir("testdata"))
			ts := httptest.NewServer(fs)
			t.Cleanup(ts.Close)

			crawler := pypi.NewCrawler(pypi.WithURL(ts.URL))
			got, err := crawler.DetectSrc(context.Background(), tt.pkg)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got.String())
		})
	}
}
