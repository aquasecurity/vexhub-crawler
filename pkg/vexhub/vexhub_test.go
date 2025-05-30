package vexhub_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vexhub-crawler/pkg/manifest"
	"github.com/aquasecurity/vexhub-crawler/pkg/vexhub"
)

func TestGenerateIndex(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(root string) error
		wantErr   require.ErrorAssertionFunc
		wantIndex string
	}{
		{
			name: "successful index generation",
			setup: func(root string) error {
				dir := filepath.Join(root, "package1")
				err := os.MkdirAll(dir, 0755)
				if err != nil {
					return err
				}
				manifestPath := filepath.Join(dir, manifest.FileName)
				manifestContent := manifest.Manifest{
					ID: "package1",
					Sources: []manifest.Source{
						{Path: "source1"},
					},
				}
				data, err := json.Marshal(manifestContent)
				if err != nil {
					return err
				}
				return os.WriteFile(manifestPath, data, 0644)
			},
			wantErr: require.NoError,
			wantIndex: `{
					"updated_at": "2025-05-20T17:16:15.123456789Z",
					"packages": [
						{ "id" : "package1", "location": "package1/source1" }
					]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			err := tt.setup(root)
			require.NoError(t, err)

			updatedAt := time.Date(2025, time.May, 20, 17, 16, 15, 123456789, time.UTC)
			err = vexhub.GenerateIndex(root, updatedAt)
			tt.wantErr(t, err)

			indexPath := filepath.Join(root, "index.json")
			data, err := os.ReadFile(indexPath)
			require.NoError(t, err)

			require.JSONEq(t, tt.wantIndex, string(data))
		})
	}
}
