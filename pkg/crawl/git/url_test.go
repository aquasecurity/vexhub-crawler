package git_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vexhub-crawler/pkg/crawl/git"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr string
	}{
		{
			name:   "happy path - GitHub URL",
			rawURL: "https://github.com/user/repo",
			want:   "git::https://github.com/user/repo.git?depth=1",
		},
		{
			name:   "happy path - GitHub URL with tree",
			rawURL: "https://github.com/user/repo/tree/main/subfolder",
			want:   "git::https://github.com/user/repo.git//subfolder?depth=1&ref=main",
		},
		{
			name:   "happy path - GitLab URL",
			rawURL: "https://gitlab.com/user/repo",
			want:   "git::https://gitlab.com/user/repo.git?depth=1",
		},
		{
			name:   "happy path - URL with existing .git suffix",
			rawURL: "https://example.com/user/repo.git",
			want:   "git::https://example.com/user/repo.git?depth=1",
		},
		{
			name:    "sad path - invalid URL",
			rawURL:  "://invalid-url",
			wantErr: "failed to parse URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := git.NormalizeURL(tt.rawURL)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got.String())
		})
	}
}
