package vex_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/sosedoff/gitkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/vex"
	"github.com/aquasecurity/vexhub-crawler/pkg/manifest"
)

var signature = &object.Signature{
	Name:  "Test",
	Email: "test@example.com",
	When:  time.Now(),
}

// NewServer creates a new Git server for testing purposes.
func NewServer(t *testing.T, repo string, setup func(*testing.T, string)) *httptest.Server {
	wtDir := t.TempDir()

	r, err := git.PlainInit(wtDir, false)
	require.NoError(t, err)

	wt, err := r.Worktree()
	require.NoError(t, err)

	setup(t, wtDir)

	_, err = wt.Add(".")
	require.NoError(t, err)

	_, err = wt.Commit("initial commit", &git.CommitOptions{
		Author: signature,
	})
	require.NoError(t, err)

	bareDir := t.TempDir()
	gitDir := filepath.Join(bareDir, repo+".git")
	_, err = git.PlainClone(gitDir, true, &git.CloneOptions{URL: wtDir})
	require.NoError(t, err)

	service := gitkit.New(gitkit.Config{
		Dir:        bareDir,
		AutoCreate: true,
		AutoHooks:  true,
	})

	// Add logging middleware
	return httptest.NewServer(service)
}

func TestCrawlPackage(t *testing.T) {
	tests := []struct {
		name         string
		purl         string
		want         openvex.VEX
		wantManifest manifest.Manifest
		wantErr      string
		setup        func(*testing.T, string) // Additional setup function for complex cases
	}{
		{
			name: "valid VEX file",
			purl: "pkg:golang/github.com/example/package@v1.2.3",
			want: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: openvex.ContextLocator(),
					ID:      "https://example.com/vex-1234",
					Author:  "Example Corp.",
					Version: 1,
				},
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{ID: "CVE-2023-1234"},
						Products: []openvex.Product{
							{
								Component: openvex.Component{
									ID: "pkg:golang/github.com/example/package@v1.2.3",
								},
							},
						},
						Status:        openvex.StatusNotAffected,
						Justification: openvex.VulnerableCodeNotPresent,
					},
				},
			},
			wantManifest: manifest.Manifest{
				ID: "pkg:golang/github.com/example/package@v1.2.3",
				Sources: []manifest.Source{
					{
						Path: "openvex.json",
						// URL will be set dynamically in the test
					},
				},
			},
		},
		{
			name: "no statements in VEX file",
			purl: "pkg:golang/github.com/example/package@v1.2.3",
			want: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: openvex.ContextLocator(),
					ID:      "https://example.com/vex-1234",
					Author:  "Example Corp.",
					Version: 1,
				},
				Statements: []openvex.Statement{},
			},
			wantErr: "no statement found",
		},
		{
			name: "PURL mismatch",
			purl: "pkg:golang/github.com/example/package@v1.2.3",
			want: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: openvex.ContextLocator(),
					ID:      "https://example.com/vex-1234",
					Author:  "Example Corp.",
					Version: 1,
				},
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{ID: "CVE-2023-1234"},
						Products: []openvex.Product{
							{
								Component: openvex.Component{
									ID: "pkg:golang/github.com/other/package@v1.2.3",
								},
							},
						},
						Status:        openvex.StatusNotAffected,
						Justification: openvex.ComponentNotPresent,
					},
				},
			},
			wantErr: "no VEX file found",
		},
		{
			name: "OCI package",
			purl: "pkg:oci/myimage@sha256:123456?repository_url=example.com/repo",
			want: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: openvex.ContextLocator(),
					ID:      "https://example.com/vex-1234",
					Author:  "Example Corp.",
					Version: 1,
				},
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{ID: "CVE-2023-1234"},
						Products: []openvex.Product{
							{
								Component: openvex.Component{
									ID: "pkg:oci/myimage@sha256:123456?repository_url=example.com/repo",
								},
							},
						},
						Status:        openvex.StatusNotAffected,
						Justification: openvex.VulnerableCodeNotPresent,
					},
				},
			},
			wantManifest: manifest.Manifest{
				ID: "pkg:oci/myimage@sha256%3A123456?repository_url=example.com%2Frepo",
				Sources: []manifest.Source{
					{
						Path: "openvex.json",
						// URL will be set dynamically in the test
					},
				},
			},
		},
		{
			name: "non-matching file",
			purl: "pkg:golang/github.com/example/package@v1.2.3",
			setup: func(t *testing.T, dir string) {
				vexDir := filepath.Join(dir, ".vex")
				err := os.MkdirAll(vexDir, 0755)
				require.NoError(t, err)

				// Create a file that doesn't match the expected pattern
				err = os.WriteFile(filepath.Join(vexDir, "not-a-vex-file.json"), []byte("{}"), 0644)
				require.NoError(t, err)
			},
			wantErr: "no VEX file found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vexHubDir := t.TempDir()

			server := NewServer(t, "testrepo", func(t *testing.T, dir string) {
				if tt.setup != nil {
					tt.setup(t, dir)
				} else {
					vexDir := filepath.Join(dir, ".vex")
					err := os.MkdirAll(vexDir, 0755)
					require.NoError(t, err)

					vexContent, err := json.Marshal(tt.want)
					require.NoError(t, err)

					err = os.WriteFile(filepath.Join(vexDir, "openvex.json"), vexContent, 0644)
					require.NoError(t, err)
				}
			})
			defer server.Close()

			purl, err := packageurl.FromString(tt.purl)
			require.NoError(t, err)

			err = vex.CrawlPackage(context.Background(), vexHubDir, "git::"+server.URL+"/testrepo.git", purl)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			var vexPath string
			if purl.Type == packageurl.TypeOCI {
				repoURL := purl.Qualifiers.Map()["repository_url"]
				vexPath = filepath.Join(vexHubDir, "pkg", purl.Type, repoURL, "openvex.json")
			} else {
				vexPath = filepath.Join(vexHubDir, "pkg", purl.Type, purl.Namespace, purl.Name, "openvex.json")
			}
			t.Logf("Looking for VEX file at: %s", vexPath)
			assert.FileExists(t, vexPath, "VEX file should exist")

			content, err := os.ReadFile(vexPath)
			require.NoError(t, err)

			// Assert VEX
			var gotVEX openvex.VEX
			err = json.Unmarshal(content, &gotVEX)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, gotVEX)

			// Assert manifest
			var manifestPath string
			if purl.Type == "oci" {
				repoURL := purl.Qualifiers.Map()["repository_url"]
				manifestPath = filepath.Join(vexHubDir, "pkg", purl.Type, repoURL, "manifest.json")
			} else {
				manifestPath = filepath.Join(vexHubDir, "pkg", purl.Type, purl.Namespace, purl.Name, "manifest.json")
			}
			t.Logf("Looking for manifest file at: %s", manifestPath)
			assert.FileExists(t, manifestPath, "Manifest file should exist")

			content, err = os.ReadFile(manifestPath)
			require.NoError(t, err)

			var gotManifest manifest.Manifest
			err = json.Unmarshal(content, &gotManifest)
			assert.NoError(t, err)

			tt.wantManifest.Sources[0].URL = server.URL + "/testrepo.git"

			assert.Equal(t, tt.wantManifest, gotManifest)
		})
	}
}
