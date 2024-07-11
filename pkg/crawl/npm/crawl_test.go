package npm_test

import (
	"context"
	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/npm"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
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
					Type: packageurl.TypeNPM,
					Name: "debug",
				},
			},
			want: "git::https://github.com/debug-js/debug.git?depth=1",
		},
		{
			name: "happy path with package with namespace",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeNPM,
					Namespace: "@babel",
					Name:      "parser",
				},
			},
			want: "git::https://github.com/babel/babel.git?depth=1",
		},
		{
			// `Repository` has been manually removed for this test
			name: "sad path with empty repo",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypeNPM,
					Name: "ms",
				},
			},
			wantErr: "no repository URL found",
		},
		{
			name: "sad path with missed package",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypeNPM,
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

			crawler := npm.NewCrawler(npm.WithURL(ts.URL + "/"))
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
