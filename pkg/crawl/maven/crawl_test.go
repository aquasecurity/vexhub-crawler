package maven_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vexhub-crawler/pkg/config"
	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/maven"
)

func TestCrawler_DetectSrc(t *testing.T) {
	tests := []struct {
		name    string
		repoDir string
		pkg     config.Package
		want    string
		wantErr string
	}{
		{
			name:    "happy path with url from `url` field",
			repoDir: filepath.Join("testdata", "url"),
			pkg: config.Package{
				// pkg:maven/com.fasterxml.jackson.core/jackson-core
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "com.fasterxml.jackson.core",
					Name:      "jackson-core",
				},
			},
			want: "git::https://github.com/FasterXML/jackson-core.git?depth=1",
		},
		{
			name:    "happy path with url from `scm.url` field",
			repoDir: filepath.Join("testdata", "scm-url"),
			pkg: config.Package{
				// pkg:maven/com.fasterxml.jackson.core/jackson-core
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "com.fasterxml.jackson.core",
					Name:      "jackson-core",
				},
			},
			want: "git::https://github.com/FasterXML/jackson-core.git?depth=1",
		},
		{
			name:    "happy path with repo from purl",
			repoDir: filepath.Join("testdata", "url"),
			pkg: config.Package{
				// pkg:maven/com.fasterxml.jackson.core/jackson-core
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "com.fasterxml.jackson.core",
					Name:      "jackson-core",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "repository_url",
							Value: "this test URL will be overwrite",
						},
					},
				},
			},
			want: "git::https://github.com/FasterXML/jackson-core.git?depth=1",
		},
		{
			name:    "happy path with ArtifactID which contains dot",
			repoDir: filepath.Join("testdata", "artifactid-with-dot"),
			pkg: config.Package{
				// pkg:maven/ai.catboost/catboost-spark-aggregate_2.11@1.2.5
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "ai.catboost",
					Name:      "catboost-spark-aggregate_2.11",
				},
			},
			want: "git::https://github.com/catboost/catboost.git?depth=1",
		},
		{
			name: "sad path with incorrect purl type",
			pkg: config.Package{
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeNPM,
					Namespace: "@babel",
					Name:      "parser",
				},
			},
			wantErr: "incorrect purl type for maven crawler",
		},
		{
			name:    "sad path when maven-metadata.xml doesn't exist",
			repoDir: filepath.Join("testdata", "no-exist"),
			pkg: config.Package{
				// pkg:maven/com.fasterxml.jackson.core/jackson-core
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "com.fasterxml.jackson.core",
					Name:      "jackson-core",
				},
			},
			wantErr: "failed to get artifact metadata: 404 Not Found",
		},
		{
			name:    "sad path with bad maven-metadata.xml",
			repoDir: filepath.Join("testdata", "bad-metadata"),
			pkg: config.Package{
				// pkg:maven/com.fasterxml.jackson.core/jackson-core
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "com.fasterxml.jackson.core",
					Name:      "jackson-core",
				},
			},
			wantErr: "XML syntax error on line",
		},
		{
			name:    "sad path when maven-metadata.xml doesn't contain latest version",
			repoDir: filepath.Join("testdata", "no-latest-version"),
			pkg: config.Package{
				// pkg:maven/com.fasterxml.jackson.core/jackson-core
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "com.fasterxml.jackson.core",
					Name:      "jackson-core",
				},
			},
			wantErr: "no latest version found",
		},
		{
			name:    "sad path when pom file doesn't exist",
			repoDir: filepath.Join("testdata", "no-pom-file"),
			pkg: config.Package{
				// pkg:maven/com.fasterxml.jackson.core/jackson-core
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "com.fasterxml.jackson.core",
					Name:      "jackson-core",
				},
			},
			wantErr: "failed to get pom file: 404 Not Found",
		},
		{
			name:    "sad path with bad pom file",
			repoDir: filepath.Join("testdata", "bad-pom"),
			pkg: config.Package{
				// pkg:maven/com.fasterxml.jackson.core/jackson-core
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "com.fasterxml.jackson.core",
					Name:      "jackson-core",
				},
			},
			wantErr: "XML syntax error on line",
		},
		{
			name:    "sad path when pom file doesn't contain url",
			repoDir: filepath.Join("testdata", "no-url"),
			pkg: config.Package{
				// pkg:maven/org.apache.xmlgraphics/batik-anim
				PURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "org.apache.xmlgraphics",
					Name:      "batik-anim",
				},
			},
			wantErr: "no repository URL found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := http.FileServer(http.Dir(tt.repoDir))
			ts := httptest.NewServer(fs)
			t.Cleanup(ts.Close)

			withUrl := maven.WithURL(ts.URL)
			if len(tt.pkg.PURL.Qualifiers) > 0 {
				tt.pkg.PURL.Qualifiers = []packageurl.Qualifier{
					{
						Key:   "repository_url",
						Value: ts.URL,
					},
				}
				withUrl = maven.WithURL("wrong-url")
			}

			crawler := maven.NewCrawler(withUrl)
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
