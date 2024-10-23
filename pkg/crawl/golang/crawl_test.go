package golang_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/golang"
)

func TestCrawler_DetectSrc(t *testing.T) {
	tests := []struct {
		name       string
		pkg        config.Package
		mockServer func(w http.ResponseWriter, r *http.Request)
		want       string
		wantErr    bool
	}{
		{
			name: "GitHub repository",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: "golang",
					Name: "github.com/example/repo",
				},
			},
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Fail(t, "unexpected HTTP call")
			},
			want:    "https://github.com/example/repo",
			wantErr: false,
		},
		{
			name: "failure - invalid import path",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: "golang",
					Name: "invalid-domain/repo",
				},
			},
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Fail(t, "unexpected HTTP call")
			},
			wantErr: true,
		},
		{
			name: "success - custom domain with go-import meta tag",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: "golang",
				},
			},
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(fmt.Sprintf(`<html><head>
					<meta name="go-import" content="%s git https://github.com/org/repo.git">
				</head></html>`, r.Host)))
				assert.NoError(t, err)
			},
			want:    "https://github.com/org/repo.git",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(tt.mockServer))
			defer ts.Close()

			u, err := url.Parse(ts.URL)
			require.NoError(t, err)

			if tt.pkg.PURL.Name == "" {
				tt.pkg.PURL.Name = u.Host
			}

			c := golang.NewCrawler()
			got, err := c.DetectSrc(context.Background(), tt.pkg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}
