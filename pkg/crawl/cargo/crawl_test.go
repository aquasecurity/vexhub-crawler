package cargo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/cargo"
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
					Type: packageurl.TypeCargo,
					Name: "typemap",
				},
			},
			want: "git::https://github.com/reem/rust-typemap.git?depth=1",
		},
		{
			name: "sad path with empty `repository` field",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypeCargo,
					Name: "empty",
				},
			},
			wantErr: "no repository URL found",
		},
		{
			name: "sad path with bad response json",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypeCargo,
					Name: "bad",
				},
			},
			wantErr: "failed to decode response",
		},
		{
			name: "sad path with missed package",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type: packageurl.TypeCargo,
					Name: "missed-package",
				},
			},
			wantErr: "failed to get package info: 404 Not Found",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "aquasecurity/vex-crawler", r.Header.Get("User-Agent"))

					f, err := os.ReadFile(filepath.Join("testdata", r.RequestURI))
					if err != nil {
						w.WriteHeader(http.StatusNotFound)
					}

					_, err = w.Write(f)
					require.NoError(t, err)
				}))
				t.Cleanup(ts.Close)

				crawler := cargo.NewCrawler(cargo.WithURL(ts.URL))
				got, err := crawler.DetectSrc(context.Background(), tt.pkg)
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			},
		)
	}
}
